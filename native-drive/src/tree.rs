use serde::Deserialize;
use std::collections::BTreeMap;
use winfsp::filesystem::FileInfo;

#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct Entry {
    #[serde(default)]
    pub id: u64,
    pub path: String,
    pub directory: bool,
    pub size: u64,
    #[serde(default)]
    pub created: i64,
    #[serde(default)]
    pub modified: i64,
}

impl Entry {
    pub fn info(&self) -> FileInfo {
        fn time(ms: i64) -> u64 {
            if ms == 0 {
                return 0;
            }
            ((ms as i128 + 11644473600000) * 10000).clamp(0, u64::MAX as i128) as u64
        }
        FileInfo {
            file_attributes: if self.directory { 0x10 } else { 0x20 },
            file_size: self.size,
            allocation_size: self.size,
            creation_time: time(self.created),
            last_write_time: time(self.modified),
            last_access_time: time(self.modified),
            change_time: time(self.modified),
            ..Default::default()
        }
    }
}

#[derive(Clone)]
pub struct Tree(pub BTreeMap<String, Entry>);

impl Tree {
    /// Move the entire subtree, retaining backend IDs and display-name casing.
    pub fn relocate(&mut self, old: &str, new: &str) -> Result<(), String> {
        let key = new.to_lowercase();
        let source = self.0.get(old).ok_or("Source not found")?.clone();
        if old == "\\" || key == "\\" || (key != old && key.starts_with(&format!("{old}\\"))) {
            return Err("Cannot move a folder into itself".into());
        }
        if key != old && self.0.contains_key(&key) {
            return Err("Destination exists".into());
        }
        if !self.0.get(parent(&key)).is_some_and(|e| e.directory) {
            return Err("Destination parent not found".into());
        }
        let entries: Vec<_> = self
            .0
            .iter()
            .filter(|(path, _)| path.as_str() == old || path.starts_with(&format!("{old}\\")))
            .map(|(path, entry)| (path.clone(), entry.clone()))
            .collect();
        for (path, mut entry) in entries {
            self.0.remove(&path);
            entry.path = format!("{new}{}", &entry.path[source.path.len()..]);
            self.0.insert(entry.path.to_lowercase(), entry);
        }
        Ok(())
    }

    pub fn empty() -> Self {
        Self(BTreeMap::from([(
            "\\".into(),
            Entry {
                id: 0,
                path: "\\".into(),
                directory: true,
                size: 0,
                created: 0,
                modified: 0,
            },
        )]))
    }

    pub fn parse(json: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Snapshot {
            entries: Vec<Entry>,
        }
        let snapshot: Snapshot = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if snapshot.entries.len() > 100000 {
            return Err("Too many entries".into());
        }
        let mut tree = Self::empty();
        for entry in snapshot.entries {
            if !entry.path.starts_with('\\')
                || entry.path == "\\"
                || entry.path[1..].split('\\').any(|part| {
                    part.is_empty()
                        || part == "."
                        || part == ".."
                        || part.encode_utf16().count() > 255
                        || part.ends_with(['.', ' '])
                        || part.chars().any(|c| c < ' ' || "/:*?\"<>|".contains(c))
                })
            {
                return Err("Invalid item path".into());
            }
            if tree.0.insert(entry.path.to_lowercase(), entry).is_some() {
                return Err("Duplicate Windows path".into());
            }
        }
        for (path, _) in tree.0.iter().filter(|(p, _)| p.as_str() != "\\") {
            let parent = parent(path);
            if !tree.0.get(parent).is_some_and(|e| e.directory) {
                return Err("Missing parent directory".into());
            }
        }
        Ok(tree)
    }
}

pub fn parent(path: &str) -> &str {
    let split = path.rfind('\\').unwrap_or(0);
    if split == 0 { "\\" } else { &path[..split] }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_listing_and_metadata() {
        let tree = Tree::parse(r#"{"entries":[{"path":"\\Docs","directory":true,"size":0},{"path":"\\Docs\\a.txt","directory":false,"size":123}]}"#).unwrap();
        assert_eq!(tree.0.len(), 3);
        assert_eq!(tree.0["\\docs\\a.txt"].info().file_size, 123);
        assert_eq!(parent("\\docs\\a.txt"), "\\docs");
    }
    #[test]
    fn rejects_traversal_or_missing_parent() {
        for path in [r"\..\bad", r"\missing\file", r"\bad:stream"] {
            let json = serde_json::json!({"entries":[{"path":path,"directory":false,"size":1}]})
                .to_string();
            assert!(Tree::parse(&json).is_err());
        }
    }

    #[test]
    fn moves_descendants_preserving_ids_and_case() {
        let mut tree = Tree::parse(
            r#"{"entries":[
            {"id":1,"path":"\\Docs","directory":true,"size":0},
            {"id":2,"path":"\\Docs\\Report.txt","directory":false,"size":12},
            {"id":3,"path":"\\Target","directory":true,"size":0}] }"#,
        )
        .unwrap();
        tree.relocate("\\docs", "\\Target\\Docs").unwrap();
        assert!(!tree.0.contains_key("\\docs"));
        assert_eq!(tree.0["\\target\\docs\\report.txt"].id, 2);
        assert_eq!(
            tree.0["\\target\\docs\\report.txt"].path,
            "\\Target\\Docs\\Report.txt"
        );
        tree.relocate("\\target\\docs", "\\Target\\DOCS").unwrap();
        assert_eq!(
            tree.0["\\target\\docs\\report.txt"].path,
            "\\Target\\DOCS\\Report.txt"
        );
    }

    #[test]
    fn invalid_moves_leave_tree_unchanged() {
        let mut tree = Tree::parse(
            r#"{"entries":[
            {"id":1,"path":"\\Docs","directory":true,"size":0},
            {"id":2,"path":"\\Docs\\Child","directory":true,"size":0},
            {"id":3,"path":"\\Target","directory":true,"size":0}] }"#,
        )
        .unwrap();
        let before = tree.0.clone();
        for target in ["\\Docs\\Child\\Docs", "\\Target", "\\missing\\Docs", "\\"] {
            assert!(tree.relocate("\\docs", target).is_err());
            assert!(tree.0 == before);
        }
        assert!(tree.relocate("\\", "\\Other").is_err());
    }
}

use serde::Deserialize;
use std::collections::BTreeMap;
use winfsp::filesystem::FileInfo;

#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct Entry {
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
            file_attributes: if self.directory { 0x10 } else { 0x1 },
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

pub struct Tree(pub BTreeMap<String, Entry>);

impl Tree {
    pub fn empty() -> Self {
        Self(BTreeMap::from([(
            "\\".into(),
            Entry {
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
}

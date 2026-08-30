use crate::tree::Tree;
use std::collections::BTreeSet;

pub struct Change {
    pub path: String,
    pub action: u32,
    pub filter: u32,
}

pub fn diff(previous: &Tree, next: &Tree) -> Vec<Change> {
    let keys: BTreeSet<_> = previous.0.keys().chain(next.0.keys()).collect();
    let mut changes = Vec::new();
    for key in keys {
        if key == "\\" {
            continue;
        }
        let before = previous.0.get(key);
        let after = next.0.get(key);
        if before == after {
            continue;
        }
        let mut push = |entry: &crate::tree::Entry, action| {
            changes.push(Change {
                // WinFsp requires uppercase notification paths when Open does not
                // supply an explicit normalized name for a case-insensitive volume.
                path: entry.path.to_uppercase(),
                action,
                filter: if entry.directory {
                    0x2
                } else {
                    0x1 | 0x4 | 0x8 | 0x10
                },
            })
        };
        match (before, after) {
            (None, Some(entry)) => push(entry, 1), // FILE_ACTION_ADDED
            (Some(entry), None) => push(entry, 2), // FILE_ACTION_REMOVED
            (Some(old), Some(new)) if old.directory != new.directory => {
                push(old, 2);
                push(new, 1);
            }
            (_, Some(entry)) => push(entry, 3), // FILE_ACTION_MODIFIED
            _ => {}
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_folder_and_child_additions_and_removals() {
        let empty = Tree::empty();
        let populated = Tree::parse(r#"{"entries":[{"path":"\\New","directory":true,"size":0},{"path":"\\New\\Child","directory":true,"size":0},{"path":"\\New\\Child\\file.txt","directory":false,"size":1}]}"#).unwrap();
        let added = diff(&empty, &populated);
        assert_eq!(added.len(), 3);
        assert!(added.iter().all(|e| e.action == 1));
        assert_eq!(added.iter().filter(|e| e.filter == 2).count(), 2);
        assert!(added.iter().any(|e| e.path == "\\NEW\\CHILD\\FILE.TXT"));
        assert!(diff(&populated, &empty).iter().all(|e| e.action == 2));
        assert!(diff(&populated, &populated).is_empty());
    }
}

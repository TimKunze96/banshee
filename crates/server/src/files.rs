//! Channel files and avatars on disk: `files/<channel id>/...` and
//! `avatars/<key>` in the data dir. Paths from clients are checked so they
//! can't leave their channel's folder.

use std::path::{Path, PathBuf};

use banshee_proto::{ChannelId, FileEntry, Key, key_hex};

pub fn channel_dir(data: &Path, channel: ChannelId) -> PathBuf {
    data.join("files").join(channel.to_string())
}

pub fn avatar_path(data: &Path, key: &Key) -> PathBuf {
    data.join("avatars").join(key_hex(key))
}

/// A client path ("/a/b.txt", "a/b.txt", "" for the top) under `root`.
pub fn resolve(root: &Path, path: &str) -> Result<PathBuf, String> {
    let mut out = root.to_path_buf();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        let bad = part == "." || part == ".." || part.contains('\\') || part.contains('\0') || part.len() > 255;
        if bad {
            return Err(format!("{part:?} can't be in a file path"));
        }
        out.push(part);
    }
    Ok(out)
}

/// The folder a path is in ("/a/b.txt" gives "/a").
pub fn parent(path: &str) -> &str {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some((p, _)) if !p.is_empty() => p,
        _ => "/",
    }
}

fn io(e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "there's no such file or folder".into(),
        std::io::ErrorKind::AlreadyExists => "that name is taken".into(),
        _ => format!("the server couldn't do that: {e}"),
    }
}

pub fn list(root: &Path, path: &str) -> Result<Vec<FileEntry>, String> {
    let dir = resolve(root, path)?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        // a channel nobody uploaded to yet
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && dir == root => return Ok(Vec::new()),
        Err(e) => return Err(io(e)),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        // uploads in progress
        if name.ends_with(".part") {
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(FileEntry { name, size: if meta.is_dir() { 0 } else { meta.len() }, modified, is_dir: meta.is_dir() });
    }
    out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(out)
}

pub fn make_dir(root: &Path, path: &str) -> Result<(), String> {
    let dir = resolve(root, path)?;
    if dir == root {
        return Err("folders need a name".into());
    }
    std::fs::create_dir_all(dir).map_err(io)
}

pub fn delete(root: &Path, path: &str) -> Result<(), String> {
    let target = resolve(root, path)?;
    if target == root {
        return Err("that's the channel's top folder".into());
    }
    match std::fs::metadata(&target).map_err(io)?.is_dir() {
        true => std::fs::remove_dir_all(target).map_err(io),
        false => std::fs::remove_file(target).map_err(io),
    }
}

pub fn rename(root: &Path, from: &str, to: &str) -> Result<(), String> {
    let (from, to) = (resolve(root, from)?, resolve(root, to)?);
    if from == root || to == root {
        return Err("that's the channel's top folder".into());
    }
    if to.exists() {
        return Err("that name is taken".into());
    }
    if to.starts_with(&from) {
        return Err("a folder can't go inside itself".into());
    }
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    std::fs::rename(from, to).map_err(io)
}

/// PNG or JPEG, judged by the first bytes.
pub fn is_picture(data: &[u8]) -> bool {
    data.starts_with(b"\x89PNG\r\n\x1a\n") || data.starts_with(&[0xff, 0xd8, 0xff])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside() {
        let root = Path::new("/data/files/1");
        assert_eq!(resolve(root, "/a/b.txt").unwrap(), root.join("a/b.txt"));
        assert_eq!(resolve(root, "").unwrap(), root);
        assert!(resolve(root, "../2/x").is_err());
        assert!(resolve(root, "a/../../x").is_err());
        assert!(resolve(root, "a\\..\\x").is_err());
        assert_eq!(parent("/a/b.txt"), "/a");
        assert_eq!(parent("/b.txt"), "/");
    }

    #[test]
    fn folders() {
        let root = std::env::temp_dir().join(format!("banshee-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(list(&root, "/").unwrap(), vec![]);
        make_dir(&root, "/docs").unwrap();
        std::fs::write(root.join("docs/a.txt"), "hi").unwrap();
        rename(&root, "/docs/a.txt", "/b.txt").unwrap();
        let names: Vec<_> = list(&root, "/").unwrap().into_iter().map(|e| (e.name, e.is_dir, e.size)).collect();
        assert_eq!(names, [("docs".into(), true, 0), ("b.txt".into(), false, 2)]);
        assert!(rename(&root, "/docs", "/docs/inner").is_err());
        delete(&root, "/docs").unwrap();
        assert_eq!(list(&root, "/").unwrap().len(), 1);
    }
}

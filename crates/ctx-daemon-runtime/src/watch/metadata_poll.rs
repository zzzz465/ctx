//! macOS fallback for appends to files that were already dirty when watched.
//! Metadata only: no content hashing and no symlink traversal.
//! The dependency's PollWatcher compares whole-second mtimes, not file lengths.
use notify::{
    event::{CreateKind, MetadataKind, ModifyKind, RemoveKind},
    Event, EventKind, RecursiveMode,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime},
};

type Handler = Arc<dyn Fn(notify::Result<Event>) + Send + Sync>;
#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
    kind: u8,
}
struct Root {
    recursive: bool,
    entries: BTreeMap<PathBuf, Stamp>,
}
pub(super) struct MetadataWatcher {
    roots: Arc<Mutex<BTreeMap<PathBuf, Root>>>,
    stop: mpsc::Sender<()>,
    stopping: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl MetadataWatcher {
    pub(super) fn new(handler: Handler) -> notify::Result<Self> {
        let roots = Arc::new(Mutex::new(BTreeMap::<PathBuf, Root>::new()));
        let watched = Arc::clone(&roots);
        let stopping = Arc::new(AtomicBool::new(false));
        let canceled = Arc::clone(&stopping);
        let (stop, receive) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("ctx-metadata-watch".to_owned())
            .spawn(move || {
                while matches!(
                    receive.recv_timeout(Duration::from_secs(5)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    let mut roots = watched
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    for (path, root) in roots.iter_mut() {
                        if canceled.load(Ordering::Acquire) {
                            return;
                        }
                        let current =
                            match scan(path, root.recursive, || canceled.load(Ordering::Acquire)) {
                                Ok(current) => current,
                                Err(error) => {
                                    if canceled.load(Ordering::Acquire) {
                                        return;
                                    }
                                    handler(Err(error));
                                    continue;
                                }
                            };
                        for (path, stamp) in &current {
                            if canceled.load(Ordering::Acquire) {
                                return;
                            }
                            let kind = match root.entries.get(path) {
                                None => Some(EventKind::Create(created_kind(stamp))),
                                Some(old) if old != stamp => Some(EventKind::Modify(
                                    ModifyKind::Metadata(MetadataKind::WriteTime),
                                )),
                                _ => None,
                            };
                            if let Some(kind) = kind {
                                handler(Ok(Event::new(kind).add_path(path.clone())));
                            }
                        }
                        for (path, stamp) in root
                            .entries
                            .iter()
                            .filter(|(path, _)| !current.contains_key(*path))
                        {
                            if canceled.load(Ordering::Acquire) {
                                return;
                            }
                            handler(Ok(Event::new(EventKind::Remove(removed_kind(stamp)))
                                .add_path(path.clone())));
                        }
                        root.entries = current;
                    }
                }
            })
            .map_err(notify::Error::io)?;
        Ok(Self {
            roots,
            stop,
            stopping,
            worker: Some(worker),
        })
    }
    pub(super) fn watch(&mut self, path: &Path, mode: RecursiveMode) -> notify::Result<()> {
        let recursive = matches!(mode, RecursiveMode::Recursive);
        let entries = scan(path, recursive, || self.stopping.load(Ordering::Acquire))?;
        self.roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_path_buf(), Root { recursive, entries });
        Ok(())
    }
    pub(super) fn unwatch(&mut self, path: &Path) -> notify::Result<()> {
        self.roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(path);
        Ok(())
    }

    pub(super) fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for MetadataWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}
// An ordinary file needs no watcher rearm, so it must not be reported with the
// `Any` kind that the event router treats as a registration change.
fn created_kind(stamp: &Stamp) -> CreateKind {
    match stamp.kind {
        0 => CreateKind::File,
        1 => CreateKind::Folder,
        _ => CreateKind::Any,
    }
}

fn removed_kind(stamp: &Stamp) -> RemoveKind {
    match stamp.kind {
        0 => RemoveKind::File,
        1 => RemoveKind::Folder,
        _ => RemoveKind::Any,
    }
}

fn scan(
    root: &Path,
    recursive: bool,
    canceled: impl Fn() -> bool,
) -> notify::Result<BTreeMap<PathBuf, Stamp>> {
    let mut entries = BTreeMap::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((path, depth)) = pending.pop() {
        if canceled() {
            return Err(notify::Error::generic("metadata watch stopped"));
        }
        if entries.len() >= 100_000 || depth > 64 {
            return Err(
                notify::Error::generic("metadata watch inventory exceeds its bound").add_path(path),
            );
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(notify::Error::io(error).add_path(path)),
        };
        let directory = metadata.file_type().is_dir();
        entries.insert(
            path.clone(),
            Stamp {
                modified: metadata.modified().ok(),
                len: metadata.len(),
                kind: if directory {
                    1
                } else if metadata.file_type().is_symlink() {
                    2
                } else {
                    0
                },
            },
        );
        if directory && (recursive || depth == 0) {
            for child in
                std::fs::read_dir(&path).map_err(|e| notify::Error::io(e).add_path(path.clone()))?
            {
                let child = child.map_err(notify::Error::io)?;
                if canceled() {
                    return Err(notify::Error::generic("metadata watch stopped"));
                }
                if pending.len() + entries.len() >= 100_000 {
                    return Err(notify::Error::generic(
                        "metadata watch inventory exceeds its bound",
                    )
                    .add_path(path));
                }
                pending.push((child.path(), depth + 1));
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn same_timestamp_append_is_reported() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temp.path().join("active.jsonl");
        let mut writer = std::fs::File::create(&path).unwrap();
        writer.write_all(b"first\n").unwrap();
        writer.flush().unwrap();
        let modified = writer.metadata().unwrap().modified().unwrap();
        let (tx, rx) = mpsc::channel();
        let mut watcher = MetadataWatcher::new(Arc::new(move |event| {
            let _ = tx.send(event);
        }))
        .unwrap();
        watcher
            .watch(temp.path(), RecursiveMode::Recursive)
            .unwrap();
        writer.write_all(b"second\n").unwrap();
        writer.flush().unwrap();
        writer
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let event = rx
            .recv_timeout(Duration::from_secs(8))
            .expect("same-time size change must be observed")
            .unwrap();
        assert!(event.paths.contains(&path));
    }

    #[test]
    fn created_and_removed_entries_report_their_file_type() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let (tx, rx) = mpsc::channel();
        let mut watcher = MetadataWatcher::new(Arc::new(move |event| {
            let _ = tx.send(event);
        }))
        .unwrap();
        watcher
            .watch(temp.path(), RecursiveMode::Recursive)
            .unwrap();
        let file = temp.path().join("new.jsonl");
        let folder = temp.path().join("subagents");
        std::fs::write(&file, b"first\n").unwrap();
        std::fs::create_dir(&folder).unwrap();
        let mut seen = BTreeMap::new();
        while seen.len() < 2 {
            let event = rx
                .recv_timeout(Duration::from_secs(8))
                .expect("created entries must be observed")
                .unwrap();
            if event.paths.contains(&file) || event.paths.contains(&folder) {
                seen.insert(event.paths[0].clone(), event.kind);
            }
        }
        assert_eq!(seen[&file], EventKind::Create(CreateKind::File));
        assert_eq!(seen[&folder], EventKind::Create(CreateKind::Folder));
        std::fs::remove_file(&file).unwrap();
        let removed = loop {
            let event = rx
                .recv_timeout(Duration::from_secs(8))
                .expect("removed file must be observed")
                .unwrap();
            if event.paths.contains(&file) {
                break event.kind;
            }
        };
        assert_eq!(removed, EventKind::Remove(RemoveKind::File));
    }

    #[test]
    fn recursive_scan_does_not_follow_symlink_descendants() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("not-a-source"), b"private").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let entries = scan(&root, true, || false).unwrap();
        assert!(entries.contains_key(&root.join("link")));
        assert!(!entries.contains_key(&root.join("link/not-a-source")));
    }

    #[test]
    fn scan_checks_shutdown_while_enumerating_children() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..8 {
            std::fs::write(temp.path().join(index.to_string()), b"").unwrap();
        }
        let checks = std::cell::Cell::new(0);
        let result = scan(temp.path(), true, || {
            checks.set(checks.get() + 1);
            checks.get() == 3
        });
        assert!(result.is_err());
        assert_eq!(checks.get(), 3);
    }

    #[test]
    fn shutdown_interrupts_the_idle_poll_wait() {
        let mut watcher = MetadataWatcher::new(Arc::new(|_| {})).unwrap();
        let start = std::time::Instant::now();
        watcher.stop();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(watcher.worker.is_none());
        watcher.stop();
    }

    #[test]
    fn scan_preserves_nonrecursive_and_depth_bounds() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("grandchild"), b"").unwrap();
        let shallow = scan(temp.path(), false, || false).unwrap();
        assert!(shallow.contains_key(&child));
        assert!(!shallow.contains_key(&child.join("grandchild")));
        let mut next = child;
        for _ in 0..64 {
            next = next.join("nested");
            std::fs::create_dir(&next).unwrap();
        }
        assert!(scan(temp.path(), true, || false).is_err());
    }
}

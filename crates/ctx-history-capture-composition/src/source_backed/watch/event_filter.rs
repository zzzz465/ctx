use super::*;
use ctx_history_provider_codex::codex::catalog::is_codex_session_rollout_path;

impl SourceBackedWatchCatalog {
    /// Proves that an event on a watched ancestor directory leaves every
    /// target of one route missing, as it was before the event. The ancestor
    /// is watched only to notice the target appearing; unrelated siblings
    /// change that directory all the time. Callers must retain rearm events.
    pub fn event_leaves_route_targets_missing(
        &self,
        route: &SourceRouteIdentity,
        event: &Path,
    ) -> bool {
        let Some(targets) = self.routes.get(route) else {
            return false;
        };
        if targets.control.is_some() || targets.targets.is_empty() {
            return false;
        }
        targets.targets.iter().all(|target| {
            target != event && target.starts_with(event) && fs::symlink_metadata(target).is_err()
        }) && fs::symlink_metadata(event).is_ok_and(|metadata| metadata.file_type().is_dir())
    }

    /// Proves that a newly created directory sits inside the single directory
    /// root of one known Codex session-tree or Claude projects-tree route.
    /// Those roots are watched recursively, so the new directory needs no
    /// watcher registration of its own; its route still reconciles.
    pub fn event_is_directory_inside_recursive_tree(
        &self,
        route: &SourceRouteIdentity,
        event: &Path,
    ) -> bool {
        let Some(targets) = self.routes.get(route) else {
            return false;
        };
        if targets.kind != Some(SourceBackedWatchTargetKind::Path) || targets.control.is_some() {
            return false;
        }
        let Some(registrations) = targets.registration_sources.as_ref() else {
            return false;
        };
        let mut roots = registrations
            .iter()
            .filter(|source| member_belongs_to_root(event, &source.source.path));
        let Some(root) = roots.next() else {
            return false;
        };
        if roots.next().is_some()
            || root.path_kind != RegisteredPathKind::Directory
            || !registration_source_is_available(root)
            || event == root.source.path
            || !matches!(
                (root.source.provider, root.source.source_format.as_ref()),
                (CaptureProvider::Codex, "codex_session_jsonl_tree")
                    | (CaptureProvider::Claude, "claude_projects_jsonl_tree")
            )
        {
            return false;
        }
        event
            .ancestors()
            .take_while(|path| path.starts_with(&root.source.path))
            .all(|path| registered_path_kind(path) == Some(RegisteredPathKind::Directory))
    }

    /// Proves that an existing unaliased file cannot be a member of one known
    /// Codex session-tree or Claude projects-tree route. Callers must retain
    /// control, rescan and rearm events: this path observation alone cannot
    /// classify topology changes.
    pub fn event_is_known_non_source_file(
        &self,
        route: &SourceRouteIdentity,
        event: &Path,
    ) -> bool {
        let Some(targets) = self.routes.get(route) else {
            return false;
        };
        if targets.kind != Some(SourceBackedWatchTargetKind::Path) || targets.control.is_some() {
            return false;
        }
        let Some(registrations) = targets.registration_sources.as_ref() else {
            return false;
        };
        let mut roots = registrations
            .iter()
            .filter(|source| member_belongs_to_root(event, &source.source.path));
        let Some(root) = roots.next() else {
            return false;
        };
        let member_name = match (root.source.provider, root.source.source_format.as_ref()) {
            (CaptureProvider::Codex, "codex_session_jsonl_tree") => {
                is_codex_session_rollout_path(event)
            }
            // Claude Code keeps titles, subagent metadata and tool-result blobs
            // beside its transcripts; discovery admits only `.jsonl` members.
            (CaptureProvider::Claude, "claude_projects_jsonl_tree") => {
                event.extension() == Some(std::ffi::OsStr::new("jsonl"))
            }
            _ => return false,
        };
        if member_name
            || roots.next().is_some()
            || root.path_kind != RegisteredPathKind::Directory
            || !registration_source_is_available(root)
        {
            return false;
        }
        fs::symlink_metadata(event).is_ok_and(|metadata| is_unaliased_file(&metadata))
            && event
                .ancestors()
                .skip(1)
                .take_while(|parent| parent.starts_with(&root.source.path))
                .all(|parent| registered_path_kind(parent) == Some(RegisteredPathKind::Directory))
    }
}

#[cfg(unix)]
fn is_unaliased_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    // A non-rollout name can still be a hard link to an eligible rollout.
    metadata.file_type().is_file() && metadata.nlink() == 1
}

#[cfg(not(unix))]
fn is_unaliased_file(_metadata: &fs::Metadata) -> bool {
    // Without a metadata-only link-count proof, retain the event. In particular,
    // the Windows handle-based checks are not available to this path observer.
    false
}

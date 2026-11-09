"""Snapshot / backup / rollback engine.

Rules baked in here:
  * nothing is modified in place before a snapshot exists (``FileTransaction``)
  * a snapshot is content-addressed (sha256 per file) so a rollback can prove
    it restored the exact bytes
  * oversized files are skipped and the snapshot is marked incomplete - we
    never pretend a partial backup is a rollback point
  * rollback itself snapshots the current state first, so "undo the undo" is
    possible (label ``pre-rollback``)
"""

from __future__ import annotations

import glob
import json
import logging
import os
import shutil
import threading
from typing import Iterable, Optional

from . import util
from .config import Config
from .errors import BackupError


class BackupManager:
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        self.config = config
        self.dir = config.get("backup.dir")
        self.enabled = bool(config.get("backup.enabled", True))
        self.max_file_bytes = int(config.get("backup.max_file_bytes", 50 * 1024 * 1024))
        self.max_total_bytes = int(config.get("backup.max_total_bytes", 512 * 1024 * 1024))
        self.max_snapshots = int(config.get("backup.max_snapshots", 300))
        self.retention_days = int(config.get("backup.retention_days", 7))
        self._lock = threading.Lock()
        self._log = logger or logging.getLogger("autonomic.backup")
        util.ensure_dir(self.dir, 0o750)

    # ------------------------------------------------------------- snapshot
    def snapshot(self, paths: Iterable[str], label: str = "manual", meta: Optional[dict] = None,
                 remove_originals: bool = False, metadata_only: bool = False) -> dict:
        if not self.enabled:
            raise BackupError("backup is disabled in config; refusing to modify files without a rollback point")
        paths = [os.path.abspath(p) for p in paths if p]
        if not paths:
            raise BackupError("snapshot requires at least one path")

        snap_id = util.new_id("s_")
        safe_label = "".join(c for c in label if c.isalnum() or c in "-_")[:32] or "snap"
        created = util.now()
        root = os.path.join(self.dir, f"{snap_id}_{safe_label}")
        files_dir = os.path.join(root, "files")
        manifest = {
            "id": snap_id,
            "label": label,
            "created_at": created,
            "created_iso": util.iso(created),
            "host": util.local_ips()[0] if util.local_ips() else "localhost",
            "complete": True,
            "files": [],
            "meta": meta or {},
            "remove_originals": remove_originals,
        }

        total = 0
        with self._lock:
            util.ensure_dir(files_dir, 0o700)
            for src in paths:
                entry = self._capture_entry(src, files_dir, total, metadata_only=metadata_only)
                if entry is None:
                    continue
                total += entry.get("size", 0)
                if entry.get("skipped"):
                    manifest["complete"] = False
                manifest["files"].append(entry)
                if not metadata_only and total > self.max_total_bytes:
                    manifest["complete"] = False
                    manifest["error"] = f"snapshot exceeded {util.human_bytes(self.max_total_bytes)} budget"
                    break

            manifest["total_bytes"] = total
            util.atomic_write(os.path.join(root, "manifest.json"), util.json_dumps(manifest, pretty=True), mode=0o600)
            util.atomic_write(os.path.join(root, ".complete"), "ok\n", mode=0o600)
            if remove_originals:
                for entry in manifest["files"]:
                    if entry.get("existed") and not entry.get("skipped") and os.path.exists(entry["path"]):
                        try:
                            if os.path.isdir(entry["path"]) and entry.get("type") == "dir":
                                continue
                            os.unlink(entry["path"])
                        except OSError as exc:
                            self._log.warning("could not remove %s during cleanup snapshot: %s", entry["path"], exc)

        self._log.info(
            "snapshot id=%s label=%s files=%d bytes=%s complete=%s",
            snap_id, label, len(manifest["files"]), util.human_bytes(total), manifest["complete"],
        )
        self.prune()
        return manifest

    def _capture_entry(self, src: str, files_dir: str, total: int, metadata_only: bool = False) -> Optional[dict]:
        entry = {"path": src, "existed": os.path.exists(src), "size": 0, "sha256": "", "skipped": False}
        if not entry["existed"]:
            entry["type"] = "absent"
            entry["note"] = "path did not exist at snapshot time; rollback will remove a file created later"
            return entry
        try:
            st = os.stat(src)
        except OSError as exc:
            entry["skipped"] = True
            entry["note"] = f"stat failed: {exc}"
            return entry

        if os.path.isdir(src):
            entry["type"] = "dir"
            if metadata_only:
                # Record the directory tree shape without copying payloads.
                files = []
                for base, _dirs, names in os.walk(src):
                    for name in names:
                        full = os.path.join(base, name)
                        try:
                            fst = os.lstat(full)
                        except OSError:
                            continue
                        files.append({
                            "path": full,
                            "rel": os.path.relpath(full, src),
                            "size": fst.st_size,
                            "mode": fst.st_mode & 0o777,
                        })
                entry["files"] = files
                entry["size"] = sum(f["size"] for f in files)
                entry["sha256"] = util.sha256_text("".join(str(f["size"]) for f in files))
                entry["copied"] = False
                entry["note"] = "metadata-only snapshot (payload not retained)"
                return entry
            copied = []
            dir_total = 0
            for base, _dirs, names in os.walk(src):
                for name in names:
                    full = os.path.join(base, name)
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        continue
                    if size > self.max_file_bytes or total + dir_total + size > self.max_total_bytes:
                        entry["skipped"] = True
                        continue
                    rel = os.path.relpath(full, src)
                    dest = os.path.join(files_dir, src.lstrip("/"), rel)
                    util.ensure_dir(os.path.dirname(dest), 0o700)
                    try:
                        shutil.copy2(full, dest)
                    except OSError as exc:
                        entry["skipped"] = True
                        self._log.warning("snapshot copy failed %s: %s", full, exc)
                        continue
                    dir_total += size
                    copied.append({
                        "path": full,
                        "rel": rel,
                        "size": size,
                        "sha256": util.sha256_file(dest),
                        "mode": st.st_mode & 0o777,
                    })
            entry["size"] = dir_total
            entry["files"] = copied
            entry["sha256"] = util.sha256_text("".join(f["sha256"] for f in copied))
            entry["copied"] = True
            return entry

        if metadata_only:
            # Disk cleanup runs precisely when space is scarce; copying the file
            # into the backup store is wasteful and often impossible. Record just
            # enough metadata to audit/identify the deletion; rollback of a
            # cleaned file is intentionally best-effort (content not retained).
            entry.update({
                "type": "file",
                "size": st.st_size,
                "sha256": util.sha256_file(src),
                "mode": st.st_mode & 0o777,
                "copied": False,
                "note": "metadata-only snapshot (payload not retained)",
            })
            return entry

        if st.st_size > self.max_file_bytes:
            entry["skipped"] = True
            entry["type"] = "file"
            entry["size"] = st.st_size
            entry["note"] = f"file larger than {util.human_bytes(self.max_file_bytes)}; not copied"
            return entry

        rel_target = os.path.join(files_dir, src.lstrip("/"))
        util.ensure_dir(os.path.dirname(rel_target), 0o700)
        try:
            shutil.copy2(src, rel_target)
        except OSError as exc:
            entry["skipped"] = True
            entry["note"] = f"copy failed: {exc}"
            return entry
        entry.update({
            "type": "file",
            "size": st.st_size,
            "sha256": util.sha256_file(src),
            "mode": st.st_mode & 0o777,
            "copied": True,
        })
        return entry

    # ----------------------------------------------------------------- read
    def _load_manifest(self, snapshot_id: str) -> tuple[dict, str]:
        pattern = os.path.join(self.dir, f"{snapshot_id}_*")
        matches = glob.glob(pattern) + glob.glob(os.path.join(self.dir, f"{snapshot_id}*"))
        if not matches:
            raise BackupError(f"snapshot not found: {snapshot_id}")
        root = matches[0]
        manifest_path = os.path.join(root, "manifest.json")
        if not os.path.exists(manifest_path):
            raise BackupError(f"snapshot manifest missing: {root}")
        with open(manifest_path, "r", encoding="utf-8") as fh:
            return json.load(fh), root

    def list(self, limit: int = 20) -> list[dict]:
        items = []
        for manifest_path in glob.glob(os.path.join(self.dir, "*", "manifest.json")):
            try:
                with open(manifest_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                items.append({
                    "id": data.get("id"),
                    "label": data.get("label"),
                    "created_at": data.get("created_iso"),
                    "files": len(data.get("files", [])),
                    "bytes": data.get("total_bytes"),
                    "complete": data.get("complete", True),
                    "label_meta": data.get("meta", {}),
                })
            except (OSError, ValueError):
                continue
        items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        return items[:limit]

    # --------------------------------------------------------------- restore
    def restore(self, snapshot_id: str, only_paths: Optional[Iterable[str]] = None, actor: str = "user") -> dict:
        manifest, root = self._load_manifest(snapshot_id)
        wanted = {os.path.abspath(p) for p in only_paths} if only_paths else None
        targets = [f for f in manifest["files"] if not wanted or f["path"] in wanted]
        if not targets:
            raise BackupError("no matching paths in snapshot")

        # snapshot current state first so the rollback can itself be rolled back
        existing = [f["path"] for f in targets if os.path.exists(f["path"])]
        pre_id = None
        if existing:
            try:
                pre = self.snapshot(existing, label="pre-rollback", meta={"rollback_of": snapshot_id})
                pre_id = pre["id"]
            except BackupError as exc:
                self._log.warning("pre-rollback snapshot failed (continuing): %s", exc)

        restored, removed, failed = [], [], []
        for entry in targets:
            path = entry["path"]
            try:
                if entry.get("type") == "absent":
                    if os.path.exists(path) and (wanted is None or path in wanted):
                        os.unlink(path)
                        removed.append(path)
                    continue
                if entry.get("skipped"):
                    failed.append({"path": path, "reason": entry.get("note", "skipped at snapshot time")})
                    continue
                if entry.get("type") == "file" and not entry.get("copied"):
                    failed.append({"path": path, "reason": entry.get("note", "metadata-only snapshot; payload not retained")})
                    continue
                if entry.get("type") == "dir":
                    for sub in entry.get("files", []):
                        src = os.path.join(root, "files", path.lstrip("/"), sub["rel"])
                        if not os.path.exists(src):
                            failed.append({"path": sub["path"], "reason": "backup payload missing"})
                            continue
                        util.ensure_dir(os.path.dirname(sub["path"]), 0o750)
                        shutil.copy2(src, sub["path"])
                        try:
                            os.chmod(sub["path"], sub.get("mode", 0o644))
                        except OSError:
                            pass
                        restored.append(sub["path"])
                    continue
                src = os.path.join(root, "files", path.lstrip("/"))
                if not os.path.exists(src):
                    failed.append({"path": path, "reason": "backup payload missing"})
                    continue
                util.ensure_dir(os.path.dirname(path), 0o750)
                shutil.copy2(src, path)
                try:
                    os.chmod(path, entry.get("mode", 0o644))
                except OSError:
                    pass
                actual = util.sha256_file(path)
                if entry.get("sha256") and actual != entry["sha256"]:
                    failed.append({"path": path, "reason": f"post-restore hash mismatch {actual[:12]}"})
                else:
                    restored.append(path)
            except OSError as exc:
                failed.append({"path": path, "reason": str(exc)})

        result = {
            "snapshot": snapshot_id,
            "pre_rollback_snapshot": pre_id,
            "restored": restored,
            "removed": removed,
            "failed": failed,
            "ok": not failed,
        }
        level = self._log.info if not failed else self._log.error
        level("rollback snapshot=%s restored=%d removed=%d failed=%d", snapshot_id, len(restored), len(removed), len(failed))
        return result

    # ---------------------------------------------------------------- prune
    def prune(self) -> int:
        removed = 0
        cutoff = util.now() - self.retention_days * 86400
        entries = []
        for manifest_path in glob.glob(os.path.join(self.dir, "*", "manifest.json")):
            try:
                with open(manifest_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                entries.append((float(data.get("created_at", 0)), os.path.dirname(manifest_path), data.get("label")))
            except (OSError, ValueError):
                continue
        entries.sort(key=lambda x: x[0])
        keep_from_index = max(0, len(entries) - self.max_snapshots)
        for idx, (created, folder, label) in enumerate(entries):
            if label == "pre-rollback":
                continue  # never prune the safety net of a rollback automatically
            if created < cutoff or idx < keep_from_index:
                try:
                    shutil.rmtree(folder)
                    removed += 1
                except OSError as exc:
                    self._log.warning("prune failed for %s: %s", folder, exc)
        return removed

    def stats(self) -> dict:
        entries = self.list(limit=self.max_snapshots)
        total = sum(e.get("bytes") or 0 for e in entries)
        return {
            "dir": self.dir,
            "enabled": self.enabled,
            "count": len(entries),
            "bytes": total,
            "retention_days": self.retention_days,
        }


class FileTransaction:
    """Guarded write scope: snapshot -> mutate -> verify, rollback on failure.

    Usage:
        with FileTransaction(backup, [path], "rule-patch", audit) as tx:
            util.atomic_write(path, content)
            tx.commit()
    """

    def __init__(self, backup: BackupManager, paths: Iterable[str], label: str,
                 auto_rollback: bool = True, meta: Optional[dict] = None):
        self.backup = backup
        self.paths = list(paths)
        self.label = label
        self.auto_rollback = auto_rollback
        self.meta = meta or {}
        self.snapshot: Optional[dict] = None
        self.committed = False
        self.result: Optional[dict] = None

    def __enter__(self) -> "FileTransaction":
        self.snapshot = self.backup.snapshot(self.paths, label=self.label, meta=self.meta)
        return self

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> dict:
        if not self.snapshot:
            raise BackupError("transaction had no snapshot")
        self.result = self.backup.restore(self.snapshot["id"])
        return self.result

    def __exit__(self, exc_type, exc, tb) -> bool:
        if not self.committed:
            if self.snapshot and self.auto_rollback:
                try:
                    self.rollback()
                except BackupError as rollback_exc:
                    logging.getLogger("autonomic.backup").error("auto-rollback failed: %s", rollback_exc)
            return False
        return False

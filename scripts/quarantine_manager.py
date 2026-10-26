
#!/usr/bin/env python3
"""Cortex Security evidence-copy utility.

Copies a regular file into an evidence directory, verifies its SHA-256,
and writes a manifest. The original is never intentionally deleted.
This is not antivirus quarantine or malware containment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quarantine_copy(source: Path, quarantine_root: Path) -> dict:
    # Check the original path before resolving it, so a final-component
    # symlink is rejected rather than silently followed.
    source = Path(os.path.abspath(source))
    try:
        source_stat = source.lstat()
    except OSError as exc:
        raise ValueError(f"Cannot inspect source path: {exc}") from exc

    if stat.S_ISLNK(source_stat.st_mode):
        raise ValueError("Source must not be a symbolic link.")

    if not stat.S_ISREG(source_stat.st_mode):
        raise ValueError("Source must be a regular file.")

    source_resolved = source.resolve(strict=True)
    quarantine_root = quarantine_root.resolve()

    if quarantine_root == source_resolved or quarantine_root in source_resolved.parents:
        raise ValueError("Evidence directory must not be inside the source file's parent tree.")

    quarantine_root.mkdir(parents=True, exist_ok=True)

    # Open without following a final-component symlink where supported.
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(source, flags)
    except OSError as exc:
        raise ValueError(f"Cannot safely open source file: {exc}") from exc

    try:
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ValueError("Opened source is not a regular file.")
        if (opened_stat.st_dev, opened_stat.st_ino) != (
            source_stat.st_dev, source_stat.st_ino
        ):
            raise ValueError("Source changed during validation; refusing to copy.")

        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
        before = digest.hexdigest()
    finally:
        os.close(fd)

    dest = quarantine_root / f"{before}_{source.name}.evidence"
    if dest.exists():
        raise FileExistsError(f"Evidence destination already exists: {dest}")

    # Copy only after validating and hashing the source. Recheck the hash
    # after copying; reject evidence if the source changed during the operation.
    shutil.copyfile(source, dest)
    after = sha256_file(dest)
    source_after = sha256_file(source)

    if before != after or before != source_after:
        dest.unlink(missing_ok=True)
        raise IOError("Hash verification failed or source changed; evidence copy removed.")

    manifest = {
        "schema_version": "0.5.3",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "original_path": str(source_resolved),
        "evidence_path": str(dest.resolve()),
        "sha256": before,
        "size_bytes": dest.stat().st_size,
        "operation": "verified_copy_only",
        "source_removed": False,
        "warning": (
            "This evidence copy is not a substitute for antivirus quarantine "
            "and does not stop a running process."
        ),
    }

    manifest_path = quarantine_root / f"{before}_{source.name}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Specific file to preserve for inspection")
    parser.add_argument("--quarantine-dir", required=True, help="Dedicated evidence directory")
    args = parser.parse_args()

    try:
        result = quarantine_copy(Path(args.file), Path(args.quarantine_dir))
        print(json.dumps(result, indent=2))
        print("Evidence copy created; original file was NOT removed or disabled.")
        print("Do not open or execute suspicious evidence. Use an isolated analysis environment.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Evidence copy failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

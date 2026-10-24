import os
import platform
from datetime import datetime


def _get_creation_time(stats):
    system = platform.system()
    if system == "Windows":
        return stats.st_ctime
    return getattr(stats, "st_birthtime", stats.st_ctime)


def _path_depth(path):
    normalized = path.replace("\\", "/")
    return normalized.count("/")


def scan_directory_with_metadata(root_path, exclude_extensions=None):
    exclude_extensions = exclude_extensions or []
    artifacts = []

    for current_root, _dirs, files in os.walk(root_path):
        for filename in files:
            if any(filename.endswith(ext) for ext in exclude_extensions):
                continue

            full_path = os.path.join(current_root, filename)

            try:
                stats = os.stat(full_path)
            except (PermissionError, FileNotFoundError, OSError):
                continue

            metadata = {
                "path": full_path,
                "size": stats.st_size,
                "path_depth": _path_depth(full_path),
                "created": datetime.fromtimestamp(_get_creation_time(stats)),
                "modified": datetime.fromtimestamp(stats.st_mtime),
                "accessed": datetime.fromtimestamp(stats.st_atime),
            }
            artifacts.append(metadata)

    return artifacts
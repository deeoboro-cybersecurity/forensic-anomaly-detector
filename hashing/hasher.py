import hashlib


def hash_file(file_path, chunk_size=4096):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(byte_block)
    except (PermissionError, FileNotFoundError, OSError):
        return None

    return sha256_hash.hexdigest()
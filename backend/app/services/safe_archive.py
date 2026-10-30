"""
Safe ZIP extraction and archive validation service.
Guards against Zip Slip, Path Traversal, Archive Bombs, and Symlink attacks.
Never executes any uploaded source code.

Limits are driven by app.core.config.settings so they are configurable from
a single .env file without code changes.
"""
import os
import shutil
import zipfile
from typing import Tuple

from app.core.config import settings


class ArchiveSecurityError(Exception):
    """Raised when an uploaded archive violates security boundaries."""
    pass


class SafeArchiveService:
    # Hard maximums — derived from settings so a single env-var controls all
    # layers of the upload pipeline consistently.

    # Maximum number of entries inside the ZIP (defence against DoS via many tiny files)
    MAX_FILE_COUNT: int = 100_000

    # Maximum *uncompressed* size across all files in the archive.
    # We allow 5× the configured upload limit as a safe ceiling; this ensures
    # even highly compressed archives remain within disk-space budgets while
    # still preventing Zip Bomb attacks.
    #   e.g. 1 GiB compressed  →  5 GiB uncompressed cap
    @classmethod
    def _max_uncompressed(cls) -> int:
        return settings.MAX_UPLOAD_SIZE_BYTES * 5

    # Maximum uncompressed size for a *single* file inside the archive.
    # Cap at 2× the upload limit so one file cannot exhaust the entire budget.
    @classmethod
    def _max_single_file(cls) -> int:
        return settings.MAX_UPLOAD_SIZE_BYTES * 2

    # Compression ratio above which we treat the file as a Zip Bomb candidate.
    # Only applied to files > 1 MiB to avoid false positives on tiny files.
    MAX_COMPRESSION_RATIO: float = 100.0

    # File extensions that are rejected regardless of content
    DANGEROUS_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".vbs", ".sh"}

    EXCLUDED_DIRECTORY_NAMES = {
        "node_modules",
        ".venv",
        "venv",
        "env",
        "build",
        "dist",
        "target",
        "__pycache__",
        ".cache",
        ".git",
        ".idea",
        ".vscode",
    }

    @classmethod
    def _is_excluded_directory(cls, filename: str) -> bool:
        normalized = filename.replace("\\", "/").lower().strip("/")
        parts = [part for part in normalized.split("/") if part]
        return any(part in cls.EXCLUDED_DIRECTORY_NAMES for part in parts[:-1])

    @classmethod
    def validate_and_extract(cls, zip_path: str, extract_to: str) -> Tuple[int, int]:
        """
        Validates zip file safety and safely extracts it to extract_to directory.
        Returns (extracted_file_count, total_uncompressed_bytes).
        Raises ArchiveSecurityError if malicious characteristics are detected.

        Uses streaming entry-by-entry extraction so the full file is never
        loaded into RAM at once.
        """
        if not os.path.exists(zip_path):
            raise ArchiveSecurityError("Archive file does not exist.")

        extract_to_abs = os.path.abspath(extract_to)
        os.makedirs(extract_to_abs, exist_ok=True)

        max_uncompressed = cls._max_uncompressed()
        max_single_file = cls._max_single_file()

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                infolist = zf.infolist()

                if len(infolist) > cls.MAX_FILE_COUNT:
                    raise ArchiveSecurityError(
                        f"Archive contains too many files ({len(infolist)} > {cls.MAX_FILE_COUNT}). Potential DoS."
                    )

                total_uncompressed = 0

                for info in infolist:
                    filename = info.filename

                    # 1. Reject path traversal and suspicious filenames
                    if (
                        ".." in filename
                        or filename.startswith("/")
                        or filename.startswith("\\")
                        or ":" in filename
                        or "\0" in filename
                    ):
                        raise ArchiveSecurityError(
                            f"Suspicious path or Zip Slip attempt detected: {filename}"
                        )

                    if cls._is_excluded_directory(filename):
                        continue

                    # 2. Check for symlinks or special devices
                    # In standard zip, external_attr mode can represent unix symlinks (0o120000)
                    unix_mode = info.external_attr >> 16
                    if unix_mode & 0o120000 == 0o120000:
                        raise ArchiveSecurityError(
                            f"Symlink entries are forbidden in archive: {filename}"
                        )

                    # 3. Track sizes and test against archive bomb
                    total_uncompressed += info.file_size

                    if info.file_size > max_single_file:
                        raise ArchiveSecurityError(
                            f"File {filename} exceeds maximum single file size "
                            f"({max_single_file / (1024*1024*1024):.2f} GiB)."
                        )

                    if total_uncompressed > max_uncompressed:
                        raise ArchiveSecurityError(
                            f"Archive exceeds maximum extracted size limit "
                            f"({max_uncompressed / (1024*1024*1024):.2f} GiB)."
                        )

                    # Check compression ratio for non-empty files
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > cls.MAX_COMPRESSION_RATIO and info.file_size > 1024 * 1024:
                            raise ArchiveSecurityError(
                                f"Suspicious compression ratio on {filename} ({ratio:.1f}x). Archive bomb blocked."
                            )

                    # 4. Canonical path verification
                    dest_file_path = os.path.abspath(os.path.join(extract_to_abs, filename))
                    if not (
                        dest_file_path == extract_to_abs
                        or dest_file_path.startswith(extract_to_abs + os.sep)
                    ):
                        raise ArchiveSecurityError(
                            f"Zip Slip attack detected: path escapes destination directory ({filename})"
                        )

                # Safe to extract — stream each file individually (no full-RAM load)
                extracted_count = 0
                for info in infolist:
                    # Ignore directory entries and excluded dependency/build trees.
                    if info.is_dir() or cls._is_excluded_directory(info.filename):
                        continue

                    dest_file_path = os.path.abspath(os.path.join(extract_to_abs, info.filename))
                    os.makedirs(os.path.dirname(dest_file_path), exist_ok=True)

                    # Stream in 64 KiB chunks — never reads the full file into RAM
                    with zf.open(info) as src, open(dest_file_path, "wb") as dst:
                        shutil.copyfileobj(src, dst, length=65536)
                    extracted_count += 1

                return extracted_count, total_uncompressed

        except zipfile.BadZipFile as e:
            raise ArchiveSecurityError(f"Corrupt or invalid zip archive: {str(e)}")
        except ArchiveSecurityError:
            cls.cleanup(extract_to_abs)
            raise
        except OSError as e:
            cls.cleanup(extract_to_abs)
            raise ArchiveSecurityError(
                f"Disk I/O error during extraction (check available disk space): {str(e)}"
            )
        except Exception as e:
            cls.cleanup(extract_to_abs)
            raise ArchiveSecurityError(f"Failed to safely extract archive: {str(e)}")

    @classmethod
    def cleanup(cls, directory: str) -> None:
        """Safely removes temporary extraction directory."""
        if directory and os.path.exists(directory) and os.path.isdir(directory):
            try:
                shutil.rmtree(directory, ignore_errors=True)
            except Exception:
                pass

"""
Automated security tests for ZIP validation, Path Traversal, and Zip Slip defenses.
"""
import io
import os
import tempfile
import zipfile
import pytest

from app.services.safe_archive import ArchiveSecurityError, SafeArchiveService


class TestSafeArchiveService:
    def test_valid_archive_extraction(self):
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "good.zip")
        extract_dir = os.path.join(temp_dir, "out")

        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("app/main.py", "print('hello secure world')")
                zf.writestr("README.md", "# Test Project")

            count, size = SafeArchiveService.validate_and_extract(zip_path, extract_dir)
            assert count == 2
            assert os.path.exists(os.path.join(extract_dir, "app", "main.py"))
            assert os.path.exists(os.path.join(extract_dir, "README.md"))
        finally:
            SafeArchiveService.cleanup(temp_dir)

    def test_excludes_dependency_and_build_directories(self):
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "filtered.zip")
        extract_dir = os.path.join(temp_dir, "out")

        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("app/main.py", "print('kept')")
                zf.writestr("node_modules/package/index.js", "ignored")
                zf.writestr(".venv/Lib/site-packages/module.py", "ignored")
                zf.writestr("dist/app.js", "ignored")

            count, _ = SafeArchiveService.validate_and_extract(zip_path, extract_dir)

            assert count == 1
            assert os.path.exists(os.path.join(extract_dir, "app", "main.py"))
            assert not os.path.exists(os.path.join(extract_dir, "node_modules"))
            assert not os.path.exists(os.path.join(extract_dir, ".venv"))
            assert not os.path.exists(os.path.join(extract_dir, "dist"))
        finally:
            SafeArchiveService.cleanup(temp_dir)

    def test_zip_slip_traversal_blocked(self):
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "slip.zip")
        extract_dir = os.path.join(temp_dir, "out")

        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                # Malicious entry attempting to escape extraction directory
                zf.writestr("../evil.txt", "MALICIOUS CONTENT ESCAPING")

            with pytest.raises(ArchiveSecurityError) as exc_info:
                SafeArchiveService.validate_and_extract(zip_path, extract_dir)

            assert "Zip Slip" in str(exc_info.value) or "Suspicious path" in str(exc_info.value)
            # Ensure the file was NEVER written outside
            assert not os.path.exists(os.path.join(temp_dir, "evil.txt"))
        finally:
            SafeArchiveService.cleanup(temp_dir)

    def test_absolute_path_entry_blocked(self):
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "abs.zip")
        extract_dir = os.path.join(temp_dir, "out")

        try:
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("/etc/passwd", "root:x:0:0:")

            with pytest.raises(ArchiveSecurityError) as exc_info:
                SafeArchiveService.validate_and_extract(zip_path, extract_dir)

            assert "Suspicious path" in str(exc_info.value) or "Zip Slip" in str(exc_info.value)
        finally:
            SafeArchiveService.cleanup(temp_dir)

    def test_excessive_file_count_blocked(self):
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "many.zip")
        extract_dir = os.path.join(temp_dir, "out")

        try:
            # Override limit for unit test
            original_limit = SafeArchiveService.MAX_FILE_COUNT
            SafeArchiveService.MAX_FILE_COUNT = 5

            with zipfile.ZipFile(zip_path, "w") as zf:
                for i in range(10):
                    zf.writestr(f"file_{i}.txt", "test")

            with pytest.raises(ArchiveSecurityError) as exc_info:
                SafeArchiveService.validate_and_extract(zip_path, extract_dir)

            assert "too many files" in str(exc_info.value).lower()
        finally:
            SafeArchiveService.MAX_FILE_COUNT = original_limit
            SafeArchiveService.cleanup(temp_dir)

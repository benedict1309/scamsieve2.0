"""
Script đóng gói dự án thành file zip sạch (Clean Distribution Packager):
- Tự động loại bỏ hoàn toàn các thư mục rác: __pycache__, .pytest_cache, .venv, .git
- Tự động loại trừ file chứa khóa bảo mật nhạy cảm: .env
- Giữ lại đầy đủ mã nguồn, mô hình, dataset và tài liệu báo cáo
"""
import os
import zipfile
import shutil
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

EXCLUDE_DIRS = {
    "__pycache__", ".pytest_cache", ".venv", "venv", ".git", ".idea", ".vscode_test", "scratch"
}

EXCLUDE_FILES = {
    ".env", "scamsieve.db", "project_clean.zip", "psieve-extension.zip"
}

EXCLUDE_EXTENSIONS = {
    ".pyc", ".pyo", ".pyd"
}


def create_clean_zip(output_zip_name: str = "ScamSieve_Project_Clean.zip"):
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    output_path = os.path.join(project_root, output_zip_name)

    logger.info(f"Đang tiến hành dọn dẹp và đóng gói dự án từ: {project_root}")
    total_files = 0

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(project_root):
            # Lọc bỏ các thư mục rác tại chỗ
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.endswith(".egg-info")]

            for file in files:
                if file in EXCLUDE_FILES:
                    continue
                ext = os.path.splitext(file)[1].lower()
                if ext in EXCLUDE_EXTENSIONS:
                    continue

                abs_file_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_file_path, project_root)

                zipf.write(abs_file_path, rel_path)
                total_files += 1

    zip_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    logger.info(f"Đóng gói thành công file sạch: {output_zip_name}")
    logger.info(f"Tổng số file: {total_files} | Dung lượng: {zip_size_mb:.2f} MB")
    logger.info("Đã loại trừ toàn bộ: .pytest_cache, __pycache__, .env, .venv, file tạm.")


if __name__ == "__main__":
    create_clean_zip()


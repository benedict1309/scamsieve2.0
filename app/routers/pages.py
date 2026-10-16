import io
import os
import zipfile
from fastapi import APIRouter, Request, Response
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/")
def home(request: Request):
    return templates.TemplateResponse(request, "home.html")


@router.get("/test-shield")
def test_shield_page(request: Request):
    return templates.TemplateResponse(request, "extension_lab.html")


@router.get("/download/extension-zip")
def download_extension_zip():
    """Tải về toàn bộ gói tiện ích mở rộng P-Sieve định dạng ZIP."""
    zbuf = io.BytesIO()
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    extension_dir = os.path.join(base_dir, "extension")
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(extension_dir):
            for file in files:
                if file.endswith(".pyc") or "__pycache__" in root:
                    continue
                full_path = os.path.join(root, file)
                arcname = os.path.join("psieve-extension", os.path.relpath(full_path, extension_dir))
                zf.write(full_path, arcname)
    zbuf.seek(0)
    return Response(
        content=zbuf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="psieve-extension.zip"'}
    )



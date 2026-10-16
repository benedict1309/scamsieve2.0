"""
Router Báo cáo và Đóng góp Dữ liệu An ninh Cộng đồng (Crowdsourcing Reports).
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, Form, Request, UploadFile, File
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.enums import ContentType
from app.services.report_service import (
    submit_community_report,
    get_recent_public_alerts,
    get_community_stats,
)

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/report")
def report_page(request: Request, db: Session = Depends(get_db)):
    """
    Trang gửi báo cáo an ninh lừa đảo trực tuyến.
    """
    recent_alerts = get_recent_public_alerts(db, limit=8)
    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "recent_alerts": recent_alerts,
            "prefill_content": request.query_params.get("content", ""),
            "prefill_type": request.query_params.get("type", "phone"),
            "success": None,
        },
    )


@router.get("/alerts")
def alerts_page(request: Request, db: Session = Depends(get_db)):
    """
    Trang theo dõi Cảnh báo cộng đồng mới nhất từ người dân và sinh viên.
    """
    recent_alerts = get_recent_public_alerts(db, limit=20)
    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            "recent_alerts": recent_alerts,
        },
    )


@router.post("/report")
async def report_submit(
    request: Request,
    content: Optional[str] = Form(None),
    content_type: str = Form("phone"),
    scam_type: str = Form("Giả danh cơ quan / Tổ chức"),
    reporter_note: str = Form(""),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    """
    Tiếp nhận biểu mẫu báo cáo gửi từ trang /report.
    Hỗ trợ gửi số điện thoại/link/nội dung hoặc đính kèm ảnh chụp màn hình (OCR tự động).
    """
    content = (content or "").strip()
    recent_alerts = get_recent_public_alerts(db, limit=8)
    image_extracted_info = ""

    # Xử lý ảnh chụp màn hình nếu người dùng đính kèm
    if image and image.filename:
        try:
            from app.services.gemini_service import gemini_service
            image_bytes = await image.read()
            if image_bytes and len(image_bytes) > 0:
                mime_type = image.content_type or "image/jpeg"
                vision_result = gemini_service.analyze_image(image_bytes, mime_type)
                if vision_result and not vision_result.get("error"):
                    extracted_text = vision_result.get("extracted_text", "").strip()
                    extracted_phone = vision_result.get("extracted_phone", "").strip()
                    extracted_url = vision_result.get("extracted_url", "").strip()
                    category = vision_result.get("category", "").strip()
                    analysis = vision_result.get("analysis", "").strip()

                    # Nếu người dùng chưa điền nội dung, tự động trích xuất từ ảnh
                    if not content:
                        if extracted_phone:
                            content = extracted_phone
                            content_type = "phone"
                        elif extracted_url:
                            content = extracted_url
                            content_type = "url"
                        elif extracted_text:
                            # Lấy nội dung thực tế trích xuất từ ảnh
                            first_line = extracted_text.split('\n')[0].strip()
                            content = first_line[:140] if first_line else extracted_text[:140]
                            content_type = "text"
                        elif analysis:
                            first_line = analysis.split('\n')[0].strip()
                            content = first_line[:140] if first_line else analysis[:140]
                            content_type = "text"
                        else:
                            content = "Nội dung phản ánh từ ảnh chụp màn hình"
                            content_type = "text"

                    # Bổ sung toàn bộ văn bản và phân tích thị giác vào phần ghi chú / bằng chứng
                    extra_notes = []
                    if extracted_text and extracted_text not in reporter_note:
                        extra_notes.append(f"Văn bản trích xuất: {extracted_text}")
                    if analysis and analysis not in reporter_note and analysis != extracted_text:
                        extra_notes.append(f"Dấu hiệu bất thường: {analysis}")
                    if extra_notes:
                        joined_extra = " | ".join(extra_notes)
                        reporter_note = (reporter_note.strip() + " | " + joined_extra).strip(" | ") if reporter_note.strip() else joined_extra

                    if category and (scam_type in ("Khác", "Giả danh cơ quan / Tổ chức", "Dấu hiệu lừa đảo")):
                        scam_type = category
                    image_extracted_info = " Đã tự động đọc và trích xuất thông tin từ ảnh chụp màn hình."
        except Exception as e:
            logger.warning(f"Error reading image in report submission: {e}")

    if not content:
        return templates.TemplateResponse(
            request,
            "report.html",
            {
                "recent_alerts": recent_alerts,
                "error": "Vui lòng nhập số điện thoại, đường link hoặc chọn ảnh chụp màn hình cần báo cáo.",
                "prefill_content": "",
                "prefill_type": content_type,
            },
        )

    # Chuyển đổi ContentType enum
    ct_enum = ContentType.PHONE
    if content_type == "url":
        ct_enum = ContentType.URL
    elif content_type == "bank_account":
        ct_enum = ContentType.BANK_ACCOUNT
    elif content_type == "text":
        ct_enum = ContentType.TEXT

    client_ip = request.client.host if request.client else None

    report = submit_community_report(
        db=db,
        content=content,
        content_type=ct_enum,
        scam_type=scam_type,
        reporter_note=reporter_note,
        reporter_ip=client_ip,
        is_scam=True,
    )

    verif = getattr(report, "verification_result", {})
    if verif.get("is_verified"):
        success_msg = (
            f"Hệ thống đã thẩm định tự động tức thì bằng AI: ĐÃ XÁC THỰC LỪA ĐẢO "
            f"({verif.get('reason')} - Độ tin cậy: {verif.get('confidence_pct')}%). "
            f"Đối tượng đã được tự động khóa và kích hoạt bảo vệ toàn mạng lưới.{image_extracted_info}"
        )
    elif verif.get("verdict") == "SUSPICIOUS":
        success_msg = (
            f"Hệ thống đã thẩm định tự động tức thì: Ghi nhận nghi vấn "
            f"({verif.get('reason')} - Độ tin cậy: {verif.get('confidence_pct')}%). "
            f"Thông tin đã được cập nhật ngay vào bảng tin cảnh báo cộng đồng.{image_extracted_info}"
        )
    else:
        success_msg = (
            f"Báo cáo của bạn đã được ghi nhận thành công và tự động đồng bộ vào hệ thống dữ liệu an toàn chung.{image_extracted_info}"
        )

    updated_alerts = get_recent_public_alerts(db, limit=8)

    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "recent_alerts": updated_alerts,
            "success": success_msg,
            "prefill_content": "",
            "prefill_type": "phone",
        },
    )


@router.post("/api/report")
def api_quick_report(
    request: Request,
    content: str = Form(...),
    content_type: str = Form("text"),
    scam_type: str = Form("Dấu hiệu lừa đảo"),
    reporter_note: str = Form(""),
    action: str = Form("scam"),  # "scam" hoac "safe"
    db: Session = Depends(get_db),
):
    """
    API gửi báo cáo nhanh từ trang kết quả tra cứu (AJAX/Fetch).
    """
    content = content.strip()
    if not content:
        return {"success": False, "error": "Nội dung cần báo cáo không được để trống."}

    ct_enum = ContentType.TEXT
    if content_type == "phone":
        ct_enum = ContentType.PHONE
    elif content_type == "url":
        ct_enum = ContentType.URL
    elif content_type == "bank_account":
        ct_enum = ContentType.BANK_ACCOUNT

    is_scam = (action != "safe")
    client_ip = request.client.host if request.client else None

    report = submit_community_report(
        db=db,
        content=content,
        content_type=ct_enum,
        scam_type=scam_type if is_scam else "Xác nhận an toàn",
        reporter_note=reporter_note,
        reporter_ip=client_ip,
        is_scam=is_scam,
    )

    stats = get_community_stats(content, db)

    return {
        "success": True,
        "report_id": report.id,
        "total_reports": stats.get("total_reports", 1),
        "scam_count": stats.get("scam_count", 0),
        "safe_count": stats.get("safe_count", 0),
        "total_votes": stats.get("total_votes", 1),
        "safe_pct": stats.get("safe_pct", 0),
        "scam_pct": stats.get("scam_pct", 0),
        "message": (
            "Đã ghi nhận báo cáo lừa đảo vào cơ sở dữ liệu an ninh cộng đồng."
            if is_scam
            else "Đã ghi nhận phản hồi xác nhận an toàn của bạn vào hệ thống."
        ),
    }


@router.get("/api/community-stats")
def api_get_community_stats(query: str = "", db: Session = Depends(get_db)):
    """
    API tra cứu nhanh số lượng báo cáo từ cộng đồng.
    """
    return get_community_stats(query, db)


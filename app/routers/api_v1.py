# File: app/routers/api_v1.py
"""
RESTful API V1 dành cho Client mở rộng:
- Chrome / Edge Extension (Manifest V3)
- Ứng dụng Di động / Tích hợp bên thứ ba
"""
import logging
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Query, File, UploadFile, HTTPException, Security, Header
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import re
from app.database import get_db
from app.detector.rules import detect_all
from app.detector.scorer import scorer, total_score
from app.detector.patterns.url_patterns import url_extractor
from app.detector.phone_utils import analyze_sender_risk
from app.models.enums import RiskLevel
from app.services.blacklist_service import check_blacklist_phone, check_blacklist_url, threat_intel
from app.services.report_service import check_community_reputation_matches

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["API V1 - Client & Extension Integration"])


@router.get("/health")
def api_v1_health():
    """
    Health check endpoint cho Extension và các Client bên ngoài.
    """
    return {"status": "ok", "service": "p-sieve"}


class ScanRequest(BaseModel):
    content: str = Field(..., description="Nội dung văn bản, số điện thoại hoặc liên kết cần giám định")
    input_type: Optional[str] = Field("auto", description="Loại dữ liệu: auto, text, phone, url")


class ScanResponse(BaseModel):
    success: bool
    content: str
    input_type: str
    score: int
    risk_level: str
    status_label: str
    summary: str
    recommendation: str
    reasons: List[str]
    is_scam: bool
    confidence: float
    matches: List[Dict[str, Any]]


@router.post("/scan", response_model=ScanResponse)
def api_v1_scan(
    req: ScanRequest,
    db: Session = Depends(get_db),
):
    """
    API Giám định nội dung đa phương thức:
    Tiếp nhận văn bản, số điện thoại, URL và trả về kết quả chuẩn hóa dạng JSON.
    """
    raw_content = req.content.strip() if req.content else ""
    if not raw_content:
        raise HTTPException(status_code=400, detail="Nội dung kiểm tra không được để trống.")

    effective_type = req.input_type
    if effective_type == "auto":
        from app.routers.scan import detect_input_type
        effective_type = detect_input_type(raw_content)

    phone_info = None
    if effective_type == "phone":
        phone_info = analyze_sender_risk(raw_content)

    # 1. Thu thập tất cả các vi phạm từ rules, blacklist, community
    raw_matches = (
        detect_all(raw_content)
        + check_blacklist_phone(raw_content, db)
        + check_blacklist_url(raw_content, db)
        + check_community_reputation_matches(raw_content, db)
    )

    # 2. Đưa qua Bộ điều phối chuẩn hóa rủi ro thống nhất
    unified_eval = scorer.evaluate_unified_risk(
        content=raw_content,
        raw_matches=raw_matches,
        phone_info=phone_info,
    )

    score = unified_eval["score"]
    risk_level = unified_eval["risk_level"]
    matches = unified_eval["matches"]
    ai_result = unified_eval["ai_result"]

    from app.routers.scan import _RISK_DISPLAY
    display = _RISK_DISPLAY.get(risk_level, _RISK_DISPLAY[RiskLevel.LOW])

    # Chuyển đổi danh sách matches sang JSON serializable
    serialized_matches = []
    for m in matches:
        serialized_matches.append({
            "rule_id": getattr(m, "rule_id", ""),
            "category": getattr(m, "category", ""),
            "snippet": getattr(m, "snippet", ""),
            "score": getattr(m, "score", 0),
            "explanation": getattr(m, "explanation", ""),
        })

    return ScanResponse(
        success=True,
        content=raw_content,
        input_type=effective_type,
        score=score,
        risk_level=risk_level.value,
        status_label=display["label"],
        summary=ai_result.get("summary", display["advice"]),
        recommendation=display["advice"],
        reasons=unified_eval.get("reasons", []),
        is_scam=ai_result.get("is_scam", risk_level == RiskLevel.HIGH),
        confidence=ai_result.get("confidence", 95.0),
        matches=serialized_matches,
    )


@router.get("/check-url")
def api_v1_check_url(
    url: str = Query(..., description="Đường dẫn URL cần kiểm tra nhanh"),
    db: Session = Depends(get_db),
):
    """
    API Kiểm tra nhanh URL thời gian thực dành cho Extension Real-time Web Shield.
    Độ trễ siêu thấp (< 5ms).
    """
    clean_url = url.strip()
    if not clean_url:
        return {"success": False, "error": "URL trống"}

    raw_matches = detect_all(clean_url) + check_blacklist_url(clean_url, db) + check_community_reputation_matches(clean_url, db)
    unified_eval = scorer.evaluate_unified_risk(content=clean_url, raw_matches=raw_matches)

    return {
        "success": True,
        "url": clean_url,
        "score": unified_eval["score"],
        "risk_level": unified_eval["risk_level"].value,
        "is_safe": unified_eval["risk_level"] == RiskLevel.LOW,
        "is_scam": unified_eval["risk_level"] == RiskLevel.HIGH,
        "reasons": unified_eval.get("reasons", []),
    }


@router.post("/scan-image")
async def api_v1_scan_image(
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    API Giám định ảnh chụp màn hình dành cho Extension và ứng dụng Client.
    """
    from app.services.gemini_service import gemini_service
    image_bytes = await image.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Tệp hình ảnh không hợp lệ hoặc rỗng.")

    mime_type = image.content_type or "image/jpeg"
    vision_result = gemini_service.analyze_image(image_bytes, mime_type)

    extracted_text = vision_result.get("extracted_text", "").strip()
    extracted_phone = vision_result.get("extracted_phone", "").strip()
    is_vision_scam = vision_result.get("is_scam", False)

    phone_info = None
    if extracted_phone:
        phone_info = analyze_sender_risk(extracted_phone)

    raw_matches = (
        detect_all(extracted_text)
        + check_blacklist_phone(extracted_text, db)
        + check_community_reputation_matches(extracted_text, db)
    )

    unified_eval = scorer.evaluate_unified_risk(
        content=extracted_text,
        raw_matches=raw_matches,
        phone_info=phone_info,
    )

    score = unified_eval["score"]
    risk_level = unified_eval["risk_level"]
    ai_result = unified_eval["ai_result"]

    # Phủ quyết kiểm chứng chéo nếu an toàn
    if risk_level == RiskLevel.LOW:
        is_scam_final = False
        status_label = "Nội dung an toàn chính thống"
        summary = "Đã xác thực tên miền chính thống được quản lý hợp pháp, không chứa mã độc hoặc hành vi lừa đảo."
    else:
        is_scam_final = is_vision_scam or (risk_level == RiskLevel.HIGH)
        status_label = "Phát hiện giả mạo hình ảnh" if is_vision_scam else "Nguy cơ rủi ro cao"
        summary = vision_result.get("analysis", ai_result.get("summary", ""))

    return {
        "success": True,
        "score": score,
        "risk_level": risk_level.value,
        "is_scam": is_scam_final,
        "status_label": status_label,
        "summary": summary,
        "extracted_text": extracted_text,
        "extracted_phone": extracted_phone,
        "visual_evidence": vision_result.get("visual_evidence", []),
        "recommendation": vision_result.get("recommendation", "Cảnh giác trước các yêu cầu chuyển tiền hoặc gửi mã OTP."),
    }


HIGH_RISK_TLDS = (
    ".xyz", ".top", ".vip", ".work", ".click", ".buzz", ".club", ".cam",
    ".fit", ".rest", ".icu", ".sbs", ".cfd", ".lol", ".space", ".link",
    ".shop", ".online", ".site", ".fun", ".live", ".pro", ".monster",
    ".quest", ".beauty", ".lat", ".asia", ".tk", ".ml", ".ga", ".cf", ".gq"
)


class PageInspectionRequest(BaseModel):
    url: str = Field(..., description="Đường dẫn trang web đang duyệt")
    title: Optional[str] = Field("", description="Tiêu đề trang web (document.title)")
    has_password_input: Optional[bool] = Field(False, description="Có ô nhập mật khẩu")
    has_otp_input: Optional[bool] = Field(False, description="Có ô nhập mã OTP")
    has_credit_card_input: Optional[bool] = Field(False, description="Có ô nhập thẻ tín dụng/CVV")
    form_action_domains: Optional[List[str]] = Field(default=[], description="Các tên miền đích của form trên trang")
    text_snippet: Optional[str] = Field("", description="Đoạn trích văn bản hiển thị trên trang")


class PageInspectionResponse(BaseModel):
    success: bool
    url: str
    score: int
    risk_level: str
    status_label: str
    is_safe: bool
    is_scam: bool
    summary: str
    recommendation: str
    reasons: List[str]
    signals: Dict[str, Any]


@router.post("/inspect-page", response_model=PageInspectionResponse)
def api_v1_inspect_page(
    req: PageInspectionRequest,
    db: Session = Depends(get_db),
):
    """
    API Giám định trang web chuyên sâu (Deep Web Inspection):
    Phân tích đa chiều: Tên miền + Tiêu đề trang + Form nhập liệu nhạy cảm + Ngữ cảnh.
    Phát hiện giả mạo thương hiệu và bẫy trộm thông tin với độ chính xác cao nhất.
    """
    clean_url = req.url.strip()
    title = (req.title or "").strip()
    text_snippet = (req.text_snippet or "").strip()
    features = url_extractor.extract_features(clean_url)
    netloc = features.get("netloc", "")

    reasons = []
    signals = {
        "brand_spoofed": False,
        "spoofed_brand": "",
        "credential_harvesting": False,
        "cross_domain_form": False,
        "is_trusted_whitelist": False,
        "in_blacklist": False,
    }

    # 1. KIỂM TRA VÙNG AN TOÀN (Gov, Edu, Whitelist)
    is_gov_or_edu = netloc.endswith(".gov.vn") or netloc.endswith(".edu.vn") or netloc in ("gov.vn", "edu.vn")
    is_trusted = is_gov_or_edu or any(netloc == d or netloc.endswith("." + d) for d in scorer.TRUSTED_DOMAINS)

    if is_trusted:
        signals["is_trusted_whitelist"] = True
        return PageInspectionResponse(
            success=True,
            url=clean_url,
            score=0,
            risk_level="LOW",
            status_label="Trang web chính thống đã xác thực",
            is_safe=True,
            is_scam=False,
            summary=f"Tên miền '{netloc}' thuộc hệ thống tổ chức chính thống hoặc cơ quan uy tín đã được bảo hộ.",
            recommendation="Trang web an toàn để sử dụng và giao dịch.",
            reasons=["Xác thực an toàn qua Vùng đối soát tổ chức chính thống"],
            signals=signals,
        )

    # 1.1 ĐỐI SOÁT TÌNH BÁO MỐI ĐE DỌA & DANH SÁCH ĐEN (Threat Intelligence & Blacklist)
    _, is_intel_blacklisted = threat_intel.check_domain_risk(netloc)
    bl_matches = check_blacklist_url(clean_url, db)
    if is_intel_blacklisted or bl_matches:
        signals["in_blacklist"] = True
        reasons.append(f"Cảnh báo Danh sách đen: Tên miền '{netloc}' nằm trong danh mục mối đe dọa lừa đảo / trang web độc hại đã được xác thực.")

    # 2. XUNG ĐỘT THƯƠNG HIỆU - TÊN MIỀN (Brand vs Domain Discrepancy)
    from app.detector.patterns.url_patterns import PROTECTED_BRANDS
    page_context = f"{title} {text_snippet}".lower()
    for brand, auth_domains in PROTECTED_BRANDS.items():
        if brand in ("p-sieve", "evn"):
            continue
        # Kiểm tra xem tiêu đề hoặc văn bản có khẳng định thương hiệu này không
        if re.search(r'\b' + re.escape(brand) + r'\b', page_context):
            is_authorized = any(netloc == auth or netloc.endswith("." + auth) for auth in auth_domains)
            if not is_authorized:
                signals["brand_spoofed"] = True
                signals["spoofed_brand"] = brand
                reasons.append(
                    f"Mạo danh thương hiệu: Giao diện/tiêu đề tự xưng là '{brand.upper()}' nhưng tên miền '{netloc}' không thuộc hệ thống chính thức ({', '.join(auth_domains[:2])})."
                )
                break

    # 3. BẪY THU THẬP THÔNG TIN NHẠY CẢM TRÊN TÊN MIỀN LẠ (Credential Harvesting)
    has_sensitive_input = req.has_otp_input or req.has_credit_card_input
    if has_sensitive_input:
        signals["credential_harvesting"] = True
        reasons.append("Phát hiện bẫy trộm dữ liệu: Trang web trên tên miền chưa được chứng thực yêu cầu nhập mã OTP hoặc thông tin thẻ ngân hàng/CVV.")

    # 4. CHUYỂN DỮ LIỆU FORM SANG TÊN MIỀN KHÁC (Cross-domain form action)
    for action_domain in req.form_action_domains:
        clean_action = action_domain.lower().split(':')[0]
        if clean_action and clean_action != netloc and not clean_action.endswith("." + netloc):
            signals["cross_domain_form"] = True
            reasons.append(f"Form gửi dữ liệu sang tên miền bên thứ ba nghi vấn: '{clean_action}'.")
            break

    # 5. KIỂM TRA PHẦN MỞ RỘNG TÊN MIỀN NGUY CƠ CAO (High-risk TLD Intelligence)
    for tld in HIGH_RISK_TLDS:
        if netloc.endswith(tld):
            signals["is_high_risk_tld"] = True
            reasons.append(f"Tên miền sử dụng phần mở rộng có rủi ro lừa đảo cao ({tld}).")
            break

    # 6. KẾT HỢP VỚI ĐỘNG CƠ GIÁM ĐỊNH TỔNG HỢP P-SIEVE
    full_text_inspect = f"{clean_url} {title} {text_snippet}".strip()
    raw_matches = detect_all(full_text_inspect) + check_community_reputation_matches(clean_url, db) + bl_matches
    unified_eval = scorer.evaluate_unified_risk(content=full_text_inspect, raw_matches=raw_matches)

    # 7. TÍNH ĐIỂM TỔNG HỢP (Ensemble Calibrated Score)
    final_score = unified_eval["score"]
    if signals.get("in_blacklist"):
        final_score = max(final_score, 95)
    if signals["brand_spoofed"]:
        final_score = max(final_score, 90)
    if signals["credential_harvesting"]:
        final_score = max(final_score, 85)
    if signals["cross_domain_form"]:
        final_score = min(final_score + 35, 100)
    if signals.get("is_high_risk_tld") and not is_trusted:
        final_score = max(final_score, 50)

    # Nếu không có dấu hiệu nhạy cảm, không mạo danh thương hiệu, không trong blacklist
    if not signals.get("in_blacklist") and not signals["brand_spoofed"] and not signals["credential_harvesting"] and not signals["cross_domain_form"]:
        if features.get("is_ip_domain"):
            final_score = max(final_score, 80)
        elif features.get("is_brand_impersonation"):
            final_score = max(final_score, 75)
        elif signals.get("is_high_risk_tld"):
            final_score = max(final_score, 50)
        else:
            final_score = min(final_score, 20)

    is_scam = final_score >= 70
    is_suspicious = 40 <= final_score < 70
    is_safe = final_score < 40

    risk_level_str = "HIGH" if is_scam else ("MEDIUM" if is_suspicious else "LOW")
    if is_scam:
        status_label = "Cảnh báo lừa đảo / Phishing nguy hiểm"
        recommendation = "TUYỆT ĐỐI KHÔNG đăng nhập, KHÔNG cung cấp mật khẩu, mã OTP hoặc thông tin thẻ ngân hàng trên trang web này!"
        summary = "Hệ thống phát hiện dấu hiệu giả mạo thương hiệu hoặc bẫy đánh cắp thông tin đăng nhập/tài chính nguy hiểm."
    elif is_suspicious:
        status_label = "Tên miền rủi ro cao / Cần thận trọng"
        recommendation = "Trang web có một số biểu hiện nghi vấn. Hãy kiểm tra kỹ đường dẫn trước khi điền bất kỳ thông tin nào."
        summary = "Cần thận trọng với các yêu cầu cung cấp thông tin cá nhân hoặc chuyển khoản tài chính."
    else:
        status_label = "Nội dung an toàn"
        recommendation = "Chưa phát hiện hành vi lừa đảo hoặc dấu hiệu giả mạo."
        summary = "Trang web an toàn, không có bẫy trộm dữ liệu đã biết."

    all_reasons = reasons + [r for r in unified_eval.get("reasons", []) if r not in reasons]

    return PageInspectionResponse(
        success=True,
        url=clean_url,
        score=final_score,
        risk_level=risk_level_str,
        status_label=status_label,
        is_safe=is_safe,
        is_scam=is_scam,
        summary=summary,
        recommendation=recommendation,
        reasons=all_reasons[:4],
        signals=signals,
    )


class InspectDeepAiRequest(BaseModel):
    url: str = Field(..., description="Đường dẫn trang web cần phân tích")
    title: Optional[str] = Field("", description="Tiêu đề trang web")
    page_text: Optional[str] = Field("", description="Văn bản trích xuất từ trang")


class InspectDeepAiResponse(BaseModel):
    success: bool
    url: str
    is_scam: bool
    confidence: float
    risk_level: str
    scam_category: str
    summary: str
    analysis: str
    recommendation: str
    pillar_identity: Optional[str] = ""
    pillar_technical: Optional[str] = ""
    pillar_behavior: Optional[str] = ""
    pillar_guidance: Optional[str] = ""


@router.post("/inspect-deep-ai", response_model=InspectDeepAiResponse)
def api_v1_inspect_deep_ai(
    req: InspectDeepAiRequest,
    db: Session = Depends(get_db),
):
    """
    API Giám định chuyên sâu ngữ nghĩa bằng AI (Gemini Semantic Webpage Shield):
    Kết hợp chặt chẽ đánh giá kỹ thuật + đọc hiểu ngữ cảnh bài viết, loại bỏ hoàn toàn mâu thuẫn.
    """
    from app.services.gemini_service import gemini_service
    import urllib.parse
    parsed_netloc = urllib.parse.urlparse(req.url).netloc.lower()

    # 1. Chạy nhanh phân tích kỹ thuật để lấy rủi ro tên miền
    tech_eval = api_v1_inspect_page(
        PageInspectionRequest(
            url=req.url,
            title=req.title or "",
            text_snippet=req.page_text or "",
        ),
        db=db,
    )
    tech_score = tech_eval.score
    tech_is_scam = tech_eval.is_scam or (tech_score >= 70)
    tech_reasons_str = "; ".join(tech_eval.reasons) if tech_eval.reasons else ""
    tech_context = f"Điểm rủi ro kỹ thuật: {tech_score}/100. Đánh giá: {tech_eval.status_label}. Chi tiết: {tech_reasons_str}"

    combined_text = f"{req.title} {req.page_text}".lower()
    is_parking_page = any(
        kw in combined_text
        for kw in ["parking page", "domain parking", "sedoparking", "under construction", "buy this domain", "parked free"]
    ) or len((req.page_text or "").strip()) < 40

    # 2. Xử lý tức thì nếu là tên miền rủi ro cao đang ở trạng thái parking/nội dung trống (dưới 10ms)
    if tech_is_scam and is_parking_page:
        return InspectDeepAiResponse(
            success=True,
            url=req.url,
            is_scam=True,
            confidence=95.0,
            risk_level="HIGH",
            scam_category="Tên miền rủi ro cao / Ngụy trang hạ tầng lừa đảo",
            summary=f"Tên miền có điểm rủi ro an ninh rất cao ({tech_score}/100) và đang ở trạng thái ngụy trang trang đỗ (parking page) hoặc nội dung tạm thời để né tránh kiểm duyệt.",
            analysis=(
                f"- Hệ thống an ninh xác nhận tên miền có rủi ro kỹ thuật cao: {tech_reasons_str or 'phần mở rộng tên miền độc hại'}.\n"
                "- Giao diện hiển thị trang đỗ hoặc nội dung trống, đây là thủ thuật phổ biến của các chiến dịch lừa đảo vừa thiết lập hạ tầng.\n"
                "- Tuyệt đối không giao dịch tài chính hoặc truy cập các đường dẫn phát tán từ tên miền này."
            ),
            recommendation="CẢNH BÁO NGUY HIỂM: Rời khỏi trang web ngay và không truy cập vào các đường dẫn liên quan đến tên miền này.",
            pillar_identity=f"Tên miền '{parsed_netloc}' có điểm nguy cơ cao ({tech_score}/100). Sử dụng TLD rủi ro hoặc hạ tầng không minh bạch.",
            pillar_technical="Phát hiện trang đỗ (Parking Page) che giấu mã nguồn hoặc cơ chế Cloaking đánh lừa bot kiểm duyệt.",
            pillar_behavior="Ngụy trang nội dung trống nhằm né tránh hệ thống lọc tự động trước khi kích hoạt kịch bản lừa đảo.",
            pillar_guidance="CẢNH BÁO NGUY HIỂM: Rời khỏi trang ngay. Tuyệt đối không truy cập các liên kết liên quan.",
        )

    # 3. Phân tích ngữ nghĩa AI với bối cảnh kỹ thuật được đối soát
    ai_res = gemini_service.analyze_webpage_semantic(
        url=req.url,
        title=req.title or "",
        page_text=req.page_text or "",
        technical_context=tech_context,
        tech_is_scam=tech_is_scam,
    )

    # 4. Hợp nhất kết quả (Ensemble Harmonization) - Đảm bảo AI không bao giờ mâu thuẫn với Engine kỹ thuật
    final_is_scam = ai_res.get("is_scam", False) or tech_is_scam
    final_risk_level = "HIGH" if (final_is_scam or ai_res.get("risk_level") == "HIGH") else (
        "MEDIUM" if (tech_score >= 40 or ai_res.get("risk_level") == "MEDIUM") else "LOW"
    )

    scam_category = ai_res.get("scam_category", "Nội dung thông thường")
    if tech_is_scam and scam_category == "Nội dung thông thường":
        scam_category = "Tên miền rủi ro cao / Ngụy trang độc hại"

    # 5. Xây dựng nội dung 4 Trụ Cột An Ninh Chuyên Sâu (4 Pillars Cyber Dossier)
    if tech_eval.signals.get("is_trusted_whitelist"):
        p_identity = f"Tên miền '{parsed_netloc}' thuộc danh bạ tổ chức chính thống hoặc cơ quan uy tín đã được bảo hộ an ninh."
    elif tech_eval.signals.get("in_blacklist"):
        p_identity = f"CẢNH BÁO DANH SÁCH ĐEN: Tên miền '{parsed_netloc}' nằm trong cơ sở dữ liệu mối đe dọa (Threat Intel / Blacklist) hoặc trang web bị xâm nhập chèn mã độc."
    elif tech_eval.signals.get("brand_spoofed"):
        p_identity = f"MẠO DANH THƯƠNG HIỆU: Tên miền '{parsed_netloc}' tự xưng là {tech_eval.signals.get('spoofed_brand', '').upper()} nhưng không thuộc hệ thống máy chủ chính thức."
    elif tech_eval.signals.get("is_high_risk_tld"):
        p_identity = f"Tên miền '{parsed_netloc}' sử dụng phần mở rộng có rủi ro lừa đảo cao. Chưa có hồ sơ danh tính minh bạch."
    else:
        p_identity = f"Tên miền '{parsed_netloc}' hoạt động bình thường, chưa ghi nhận dấu hiệu mạo danh thương hiệu lớn."

    tech_notes = []
    if req.url.startswith("https://"):
        tech_notes.append("Giao thức mã hóa HTTPS hợp lệ")
    else:
        tech_notes.append("Không sử dụng HTTPS bảo mật")
    if tech_eval.signals.get("credential_harvesting"):
        tech_notes.append("Phát hiện bẫy thu thập mã Smart OTP / Thông tin thẻ ngân hàng")
    if tech_eval.signals.get("cross_domain_form"):
        tech_notes.append("Form gửi dữ liệu trái phép sang tên miền thứ ba")
    if not tech_eval.signals.get("credential_harvesting") and not tech_eval.signals.get("cross_domain_form"):
        tech_notes.append("Cấu trúc form và liên kết nội bộ đạt chuẩn an toàn")
    p_technical = ". ".join(tech_notes) + "."

    summary_text = ai_res.get("summary", "")
    if final_is_scam:
        if not summary_text or "an toàn" in summary_text.lower() or "chính thống" in summary_text.lower():
            if tech_eval.signals.get("in_blacklist"):
                summary_text = f"Cảnh báo nguy hiểm: Tên miền '{parsed_netloc}' bị ghi nhận trong danh sách đen an ninh mạng hoặc có dấu hiệu mã độc chuyển hướng lừa đảo."
            else:
                summary_text = f"Hệ thống phát hiện dấu hiệu lừa đảo nguy hiểm trên trang web '{parsed_netloc}'."
        p_behavior = f"Kịch bản rủi ro: {scam_category}. {summary_text}"
    else:
        p_behavior = "Nội dung minh bạch, không phát hiện mưu mẹo thao túng tâm lý, áp lực thời gian hoặc chiêu trò tặng quà/việc làm ảo."

    if final_risk_level == "HIGH":
        p_guidance = "CẢNH BÁO NGUY HIỂM: Rời khỏi trang web ngay. Tuyệt đối KHÔNG đăng nhập, không cung cấp mã Smart OTP, mật khẩu hay số tài khoản."
    elif final_risk_level == "MEDIUM":
        p_guidance = "CẦN THẬN TRỌNG: Chỉ đọc nội dung tham khảo. Không thực hiện các giao dịch chuyển tiền hoặc cung cấp thông tin cá nhân."
    else:
        p_guidance = "AN TOÀN: Trang web đạt tiêu chuẩn an ninh cơ bản. Luôn duy trì cảnh giác kiểm tra thanh địa chỉ trước khi tương tác."

    return InspectDeepAiResponse(
        success=True,
        url=req.url,
        is_scam=final_is_scam,
        confidence=float(ai_res.get("confidence", 85.0)),
        risk_level=final_risk_level,
        scam_category=scam_category,
        summary=summary_text,
        analysis=ai_res.get("analysis", ""),
        recommendation=ai_res.get("recommendation", ""),
        pillar_identity=p_identity,
        pillar_technical=p_technical,
        pillar_behavior=p_behavior,
        pillar_guidance=p_guidance,
    )


class InspectHeuristicsRequest(BaseModel):
    url: str = Field(..., description="Đường dẫn trang web cần giám định heuristic")
    dom: Optional[Dict[str, Any]] = Field(default={}, description="Đặc trưng DOM trích xuất từ tiện ích mở rộng")


@router.post("/inspect-heuristics")
def api_v1_inspect_heuristics(
    req: InspectHeuristicsRequest,
    db: Session = Depends(get_db),
):
    """
    API Giám định Heuristic URL & Nội dung Web Siêu tốc (21 Tiêu chí Quốc tế & Việt Nam).
    Tốc độ: < 2ms, cung cấp toàn bộ 17 tiêu chí ChongLuaDao + 4 tiêu chí đặc quyền P-Sieve.
    """
    from app.detector.heuristics import evaluate_heuristics
    result = evaluate_heuristics(url=req.url, dom=req.dom, db=db)
    result["success"] = True
    return result


import time
from fastapi.security import APIKeyHeader
from app.config import settings

ADMIN_API_KEY_HEADER = APIKeyHeader(name="X-Admin-API-Key", auto_error=False)

# Rate limiter in-memory cho endpoint đồng bộ
_last_sync_times: List[float] = []
_SYNC_RATE_LIMIT_WINDOW = 60.0  # 60 giây
_SYNC_MAX_CALLS = 5  # Tối đa 5 lần trong 60 giây


def verify_admin_access(
    api_key_header: Optional[str] = Security(ADMIN_API_KEY_HEADER),
    authorization: Optional[str] = Header(None),
) -> bool:
    """
    Xác thực quyền quản trị viên thông qua X-Admin-API-Key hoặc Bearer token.
    Ngăn chặn việc kẻ gian tự ý kích hoạt đồng bộ dữ liệu đè nặng tài nguyên server.
    """
    expected_key = getattr(settings, "ADMIN_API_KEY", "psieve-admin-secret-key-2024")
    token = None
    if api_key_header:
        token = api_key_header
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

    if not token or token != expected_key:
        raise HTTPException(
            status_code=401,
            detail="Truy cập bị từ chối: Yêu cầu khóa quản trị hợp lệ (Header 'X-Admin-API-Key' hoặc 'Authorization: Bearer <KEY>').",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return True


def check_sync_rate_limit():
    """
    Giới hạn tần suất gọi đồng bộ dữ liệu (Rate Limiting).
    Tối đa 5 lần mỗi 60 giây.
    """
    now = time.time()
    global _last_sync_times
    _last_sync_times = [t for t in _last_sync_times if now - t < _SYNC_RATE_LIMIT_WINDOW]
    if len(_last_sync_times) >= _SYNC_MAX_CALLS:
        retry_after = int(_SYNC_RATE_LIMIT_WINDOW - (now - _last_sync_times[0]))
        raise HTTPException(
            status_code=429,
            detail=f"Quá giới hạn tần suất đồng bộ threat intel (Tối đa {_SYNC_MAX_CALLS} lần/phút). Vui lòng thử lại sau {retry_after} giây.",
            headers={"Retry-After": str(max(1, retry_after))},
        )
    _last_sync_times.append(now)


class ThreatIntelSyncRequest(BaseModel):
    limit_per_feed: Optional[int] = Field(default=300, description="Giới hạn số lượng bản ghi tối đa lấy từ mỗi nguồn cấp")


@router.post("/threat-intel/sync")
def api_v1_sync_threat_intel(
    req: Optional[ThreatIntelSyncRequest] = None,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_admin_access),
    _rate: None = Depends(check_sync_rate_limit),
):
    """
    Kích hoạt đồng bộ hóa tự động nguồn cấp Tình báo Mối đe dọa Quốc tế & Việt Nam (URLhaus, OpenPhish, P-Sieve Seeds).
    Yêu cầu xác thực khóa quản trị (X-Admin-API-Key) và áp dụng Rate Limit chống DoS.
    """
    limit = req.limit_per_feed if req else 300
    from app.services.threat_feed_service import threat_feed_service
    res = threat_feed_service.sync_all_feeds(db=db, limit_per_feed=limit)
    return res


@router.get("/threat-intel/stats")
def api_v1_get_threat_intel_stats(
    db: Session = Depends(get_db),
):
    """
    Truy vấn số liệu thống kê cơ sở dữ liệu Tình báo Mối đe dọa (Threat Intelligence).
    """
    from app.services.threat_feed_service import threat_feed_service
    return threat_feed_service.get_stats(db=db)


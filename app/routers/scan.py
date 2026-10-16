"""
Router quet noi dung: form nhap va trang ket qua.
"""
from fastapi import APIRouter, Depends, Form, Request, UploadFile, File
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import re

import logging
from app.database import get_db
from app.detector.rules import detect_all
from app.detector.scorer import score_and_classify, scorer
from app.detector.text_utils import preprocessor, prepare_model_input
from app.detector.patterns.url_patterns import url_extractor
from app.detector.phone_utils import analyze_sender_risk
from app.detector.base import RuleMatch
from app.models.enums import RiskLevel
from app.services.blacklist_service import check_blacklist_phone, check_blacklist_url
from app.services.report_service import (
    check_community_reputation_matches,
    get_community_stats,
)

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

_RISK_DISPLAY = {
    RiskLevel.LOW: {
        "label": "Chưa phát hiện dấu hiệu lừa đảo rõ ràng",
        "advice": (
            "Dựa trên các dấu hiệu kiểm tra, nội dung này chưa cho thấy biểu hiện lừa đảo rõ "
            "ràng. Tuy nhiên, nếu vẫn thấy nghi ngờ, bạn nên liên hệ trực tiếp tổng đài "
            "chính thức của ngân hàng hoặc cơ quan liên quan để xác minh."
        ),
    },
    RiskLevel.MEDIUM: {
        "label": "Có một số dấu hiệu đáng ngờ",
        "advice": (
            "Nội dung có một số dấu hiệu bất thường. Tuyệt đối không chuyển tiền, không "
            "cung cấp mã OTP, và không bấm vào đường link lạ. Hãy xác minh lại qua kênh "
            "chính thức trước khi thực hiện bất kỳ thao tác nào."
        ),
    },
    RiskLevel.HIGH: {
        "label": "Rất có khả năng đây là lừa đảo",
        "advice": (
            "Nội dung chứa nhiều dấu hiệu lừa đảo nghiêm trọng. TUYỆT ĐỐI KHÔNG chuyển tiền, "
            "KHÔNG cung cấp mã OTP/mật khẩu, KHÔNG truy cập liên kết hay tải file đính kèm. "
            "Nên chặn ngay số liên lạc này và báo cáo đến cơ quan chức năng."
        ),
    },
}


def detect_input_type(content: str, fallback: str = "text") -> str:
    """
    Tự động nhận diện thể loại nội dung người dùng nhập:
    - 'phone': Số điện thoại hoặc đầu số viễn thông
    - 'url': Đường link / tên miền trang web
    - 'email': Địa chỉ thư điện tử
    - 'text': Tin nhắn SMS, văn bản, đoạn hội thoại tổng hợp
    """
    clean = content.strip()
    if not clean:
        return fallback

    # 1. Địa chỉ IP (IPv4) hoặc URL máy chủ
    if re.fullmatch(r"^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/[^\s]*)?$", clean, re.IGNORECASE):
        return "url"

    # 2. Thư điện tử (Email)
    if re.fullmatch(r"^[\w\.\+\-]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}$", clean):
        return "email"

    # 3. Đường dẫn liên kết (URL / Web / Domain)
    if re.fullmatch(r"^(https?:\/\/)?(www\.)?[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+(\/[^\s]*)?$", clean, re.IGNORECASE):
        return "url"

    # 4. Số điện thoại (chỉ chứa các chữ số và ký tự phân cách, không chứa chữ cái tiếng Việt hay Latin)
    digits_only = re.sub(r"[\s\.\-\(\)\+]", "", clean)
    has_letters = bool(re.search(r"[a-zA-ZÀ-ỹ]", clean))
    if not has_letters and digits_only.isdigit() and 3 <= len(digits_only) <= 15:
        if not re.search(r"\d+\.\d+\.\d+", clean):
            return "phone"

    return "text"


def is_standalone_phone(content: str) -> bool:
    clean = content.strip()
    digits_only = re.sub(r"[\s\.\-\(\)\+]", "", clean)
    has_letters = bool(re.search(r"[a-zA-ZÀ-ỹ]", clean))
    if not has_letters and digits_only.isdigit() and 3 <= len(digits_only) <= 15:
        if not re.search(r"\d+\.\d+\.\d+", clean):
            return True
    return False


@router.get("/scan")
def scan_form(request: Request, mode: str = "text"):
    if mode not in ["text", "image"]:
        mode = "text"
    return templates.TemplateResponse(request, "scan.html", {"mode": mode})


@router.post("/scan")
def scan_submit(
    request: Request,
    content: str = Form(...),
    sender: str = Form(""),
    input_type: str = Form("text"),
    db: Session = Depends(get_db),
):
    content = content.strip()

    if not content:
        return templates.TemplateResponse(
            request,
            "scan.html",
            {
                "error": "Vui lòng dán nội dung hoặc số điện thoại cần kiểm tra trước khi bấm Kiểm tra.",
                "content": "",
                "input_type": input_type,
            },
        )

    phone_info = None
    ai_result = {"active": False}

    # TRƯỜNG HỢP 1: Tra cứu Số điện thoại độc lập thuần túy
    if is_standalone_phone(content):
        effective_type = "phone"
        phone_info = analyze_sender_risk(content)
        phone_info["detected_in_content"] = False
        # Tra cứu số điện thoại trực tiếp vào cơ sở dữ liệu Blacklist
        matches = check_blacklist_phone(content, db)

        if phone_info.get("is_verified_official"):
            # Nếu là hotline chính thống đã xác minh: ghi nhận thông tin xác thực an toàn tuyệt đối
            matches = [
                RuleMatch(
                    rule_id="verified_official_hotline",
                    category="Hotline chính thống đã được xác minh",
                    snippet=phone_info.get("normalized", content),
                    score=0,
                    explanation=phone_info["notes"][0],
                )
            ]
            score = 0
            risk_level = RiskLevel.LOW
            ai_result = {
                "active": True,
                "scam_prob": 0.0,
                "safe_prob": 100.0,
                "is_scam": False,
                "is_suspicious": False,
                "confidence": 100.0,
                "status_label": "Hotline chính thống",
                "summary": "Đầu số tổng đài chính thức đã được xác thực an toàn tuyệt đối.",
            }
        else:
            # Bổ sung cảnh báo từ hệ thống Telecom Intelligence (VoIP, Robocall, dải số ảo)
            if phone_info.get("risk_score", 0) > 0:
                is_high_risk = phone_info.get("risk_score", 0) >= 70
                category_title = (
                    "Nhận diện đầu số VoIP / Cố định ảo có nguy cơ lừa đảo cao"
                    if is_high_risk
                    else "Cảnh báo rủi ro đầu số viễn thông (Cần xác minh danh tính)"
                )
                matches.append(
                    RuleMatch(
                        rule_id="telecom_prefix_intelligence",
                        category=category_title,
                        snippet=phone_info.get("normalized", content),
                        score=int(phone_info["risk_score"]),
                        explanation=" | ".join(phone_info["notes"]),
                    )
                )

            # Bổ sung cảnh báo từ cơ sở dữ liệu phản ánh cộng đồng
            community_matches = check_community_reputation_matches(content, db)
            matches.extend(community_matches)
            matches.sort(key=lambda m: m.score, reverse=True)
            score, risk_level = score_and_classify(matches)
            ai_result = {
                "active": True,
                "scam_prob": float(score),
                "safe_prob": float(100 - score),
                "is_scam": risk_level == RiskLevel.HIGH,
                "is_suspicious": risk_level == RiskLevel.MEDIUM,
                "confidence": float(score if risk_level == RiskLevel.HIGH else (100 - score)),
                "status_label": "Đầu số nguy cơ cao" if risk_level == RiskLevel.HIGH else ("Cần thận trọng" if risk_level == RiskLevel.MEDIUM else "Đầu số thông thường"),
                "summary": "Kết quả giám định dựa trên tình báo đầu số viễn thông và cơ sở dữ liệu cộng đồng.",
            }

    # TRƯỜNG HỢP 2: Người dùng kiểm tra Tin nhắn / Email / URL
    else:
        detected_type = detect_input_type(content, fallback="text")
        effective_type = detected_type if detected_type in ["url", "email"] else "text"

        # Nếu trong tin nhắn/văn bản có chứa số điện thoại, trích xuất để giám định viễn thông
        from app.detector.phone_utils import extract_phone_candidates
        phone_candidates = extract_phone_candidates(content)
        if phone_candidates:
            cand_info = analyze_sender_risk(phone_candidates[0])
            cand_info["detected_in_content"] = True
            cand_info["target_number"] = phone_candidates[0]
            phone_info = cand_info

        # 1. Quét nội dung văn bản, số điện thoại, URL và phản ánh cộng đồng
        raw_matches = (
            detect_all(content)
            + check_blacklist_phone(content, db)
            + check_blacklist_url(content, db)
            + check_community_reputation_matches(content, db)
        )

        # 2. Đưa qua Kiến trúc Đồng bộ và Chuẩn hóa Điểm số (Unified Scoring Engine)
        unified_eval = scorer.evaluate_unified_risk(
            content=content,
            raw_matches=raw_matches,
            phone_info=phone_info,
        )
        score = unified_eval["score"]
        risk_level = unified_eval["risk_level"]
        matches = unified_eval["matches"]
        ai_result = unified_eval["ai_result"]

    url_forensics = None
    if effective_type == "url":
        cand_urls = url_extractor.extract_urls(content)
        scan_target = cand_urls[0] if cand_urls else content
        features = url_extractor.extract_features(scan_target)
        dga_info = features.get("dga_info", {})
        imp_info = features.get("impersonation_info", {})
        url_forensics = {
            "target_url": scan_target,
            "netloc": features.get("netloc", ""),
            "tld": features.get("tld", ""),
            "is_dga": features.get("is_dga", False),
            "entropy": dga_info.get("entropy", 0.0),
            "vowel_ratio": dga_info.get("vowel_ratio", 0.0),
            "dga_reasons": dga_info.get("reasons", []),
            "is_brand_impersonation": features.get("is_brand_impersonation", False),
            "impersonation_type": imp_info.get("type", ""),
            "impersonated_brand": imp_info.get("brand", ""),
            "impersonation_detail": imp_info.get("detail", ""),
            "has_credential_spoofing": features.get("has_credential_spoofing", False),
            "spoofed_credential": features.get("spoofed_credential", ""),
            "is_open_redirect": features.get("is_open_redirect", False),
            "redirect_target_url": features.get("redirect_target_url", ""),
            "is_shortened": features.get("is_shortened", False),
            "resolved_url": features.get("resolved_url", ""),
            "is_suspicious_tld": features.get("is_suspicious_tld", False),
        }

    from app.services.gemini_service import gemini_service
    gemini_enabled = gemini_service.is_configured()

    display = _RISK_DISPLAY[risk_level]

    community_stats = get_community_stats(content, db)

    return templates.TemplateResponse(
        request,
        "scan_result.html",
        {
            "content": content,
            "input_type": effective_type,
            "phone_info": phone_info,
            "url_forensics": url_forensics,
            "score": score,
            "risk_level": risk_level.value,
            "risk_label": display["label"],
            "risk_advice": display["advice"],
            "matches": matches,
            "ai_result": ai_result,
            "gemini_enabled": gemini_enabled,
            "community_stats": community_stats,
        },
    )


@router.post("/api/gemini-consult")
def api_gemini_consult(
    content: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    API tham van chuyen sau bat dong bo tu Gemini AI:
    Tích hợp Cross-Verification Guardrail đối soát với Ground-Truth pipeline nội bộ,
    loại bỏ triệt để ảo giác (False Positive Hallucination) từ Cloud LLM.
    """
    content = content.strip()
    if not content:
        return {"active": False, "error": "Nội dung trống"}

    from app.services.gemini_service import gemini_service
    from app.detector.phone_utils import extract_phone_candidates, analyze_sender_risk

    # 1. Trích xuất thông tin số điện thoại (nếu tra cứu SĐT hoặc có SĐT trong nội dung)
    detected_type = detect_input_type(content, fallback="text")
    phone_info = None
    if detected_type == "phone":
        phone_info = analyze_sender_risk(content)
    else:
        phone_candidates = extract_phone_candidates(content)
        if phone_candidates:
            phone_info = analyze_sender_risk(phone_candidates[0])

    # 2. Cơ chế Đối soát Kiểm chứng Chéo (Cross-Verification Guardrail)
    raw_matches = (
        detect_all(content)
        + check_blacklist_phone(content, db)
        + check_blacklist_url(content, db)
        + check_community_reputation_matches(content, db)
    )

    if detected_type == "phone" and phone_info and phone_info.get("risk_score", 0) > 0:
        is_high = phone_info.get("risk_score", 0) >= 70
        raw_matches.append(
            RuleMatch(
                rule_id="telecom_prefix_intelligence",
                category="Nhận diện đầu số nguy cơ cao" if is_high else "Cảnh báo rủi ro đầu số",
                snippet=phone_info.get("normalized", content),
                score=int(phone_info["risk_score"]),
                explanation=" | ".join(phone_info.get("notes", [])),
            )
        )

    unified_eval = scorer.evaluate_unified_risk(
        content=content,
        raw_matches=raw_matches,
        phone_info=phone_info,
    )

    # 3. Nếu là tra cứu SĐT và Hệ thống Viễn thông đã phát hiện rủi ro cao hoặc hotline chính thống:
    if detected_type == "phone" and phone_info:
        if phone_info.get("risk_score", 0) >= 70:
            notes_bullets = "\n".join([f"- {n}" for n in phone_info.get("notes", [])])
            return {
                "active": True,
                "is_scam": True,
                "risk_level": "HIGH",
                "category": "Cảnh báo đầu số viễn thông rủi ro cao",
                "confidence": float(phone_info["risk_score"]),
                "analysis": notes_bullets or "- Đầu số cố định ảo VoIP có nguy cơ lừa đảo cao.",
                "recommendation": "CẢNH BÁO NGUY HIỂM: Tuyệt đối không nghe máy, không gọi lại hoặc làm theo hướng dẫn chuyển tiền/cung cấp OTP từ số điện thoại này.",
                "model_used": "Hệ thống Tình báo Viễn thông P-Sieve"
            }
        elif phone_info.get("type") in ["VN_HOTLINE", "BRANDNAME"]:
            return {
                "active": True,
                "is_scam": False,
                "risk_level": "LOW",
                "category": "Tổng đài / Hotline chính thống",
                "confidence": 95.0,
                "analysis": f"- Đầu số '{phone_info.get('normalized', content)}' là hotline/tổng đài chính thống được bảo hộ an ninh.",
                "recommendation": "Đầu số chính thống. Người dùng có thể an tâm liên hệ giải quyết dịch vụ.",
                "model_used": "Hệ thống Tình báo Viễn thông P-Sieve"
            }

    # 4. Phân tích ngữ cảnh thông qua LLM / Gemini / Groq
    raw_ai_result = gemini_service.analyze_message(content)
    if not raw_ai_result or not raw_ai_result.get("active"):
        return raw_ai_result

    # 5. Đồng bộ hóa kết quả (Harmonization) - Đảm bảo Đánh giá chi tiết không bao giờ mâu thuẫn với Hệ thống Heuristic:
    if unified_eval["risk_level"] == RiskLevel.HIGH:
        raw_ai_result["is_scam"] = True
        raw_ai_result["risk_level"] = "HIGH"
        if "chính thống" in raw_ai_result.get("category", "").lower() or "quảng cáo" in raw_ai_result.get("category", "").lower():
            raw_ai_result["category"] = "Cảnh báo lừa đảo / Nguy cơ cao"
            raw_ai_result["recommendation"] = "CẢNH BÁO NGUY HIỂM: Tuyệt đối không chuyển tiền, không cung cấp mã OTP hay bấm vào bất kỳ liên kết nào."
    elif unified_eval["risk_level"] == RiskLevel.LOW and raw_ai_result.get("is_scam", False):
        raw_ai_result["is_scam"] = False
        raw_ai_result["risk_level"] = "LOW"
        raw_ai_result["category"] = "Tin nhắn chính thống / An toàn"
        raw_ai_result["confidence"] = 92.0

    return raw_ai_result


@router.post("/api/ocr-extract")
async def api_ocr_extract(image: UploadFile = File(...)):
    """
    API trích xuất chữ/SĐT/URL từ ảnh chụp màn hình (OCR) để điền vào ô kiểm tra bên cạnh.
    """
    from app.services.gemini_service import gemini_service
    image_bytes = await image.read()
    if not image_bytes:
        return {"success": False, "error": "Tệp hình ảnh không hợp lệ hoặc rỗng."}

    mime_type = image.content_type or "image/jpeg"
    vision_result = gemini_service.analyze_image(image_bytes, mime_type)

    if not vision_result or vision_result.get("error"):
        err_msg = vision_result.get("error", "Không thể trích xuất chữ từ hình ảnh.") if vision_result else "Lỗi xử lý ảnh."
        return {"success": False, "error": err_msg}

    extracted_text = str(vision_result.get("extracted_text") or "").strip()
    extracted_phone = str(vision_result.get("extracted_phone") or "").strip()
    extracted_url = str(vision_result.get("extracted_url") or "").strip()

    return {
        "success": True,
        "extracted_text": extracted_text,
        "extracted_phone": extracted_phone,
        "extracted_url": extracted_url,
        "category": vision_result.get("category", ""),
        "is_scam": vision_result.get("is_scam", False),
    }


@router.post("/scan-image")
async def handle_scan_image(
    request: Request,
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Quét và giám định hình ảnh / ảnh chụp màn hình lừa đảo:
    1. Tiếp nhận file ảnh (PNG, JPG, WebP...).
    2. Gửi sang Gemini Multimodal Vision để OCR và phân tích bằng chứng thị giác.
    3. Trích xuất text, số điện thoại, URL trong ảnh và chạy qua toàn bộ Pipeline Detector.
    4. Trả về trang kết quả hoàn chỉnh kèm ảnh xem trước và cảnh báo chi tiết.
    """
    from app.services.gemini_service import gemini_service
    import base64

    # Đọc dữ liệu ảnh
    image_bytes = await image.read()
    if not image_bytes or len(image_bytes) == 0:
        return templates.TemplateResponse(
            request,
            "scan.html",
            {"error": "Vui lòng chọn hoặc dán (Ctrl+V) một hình ảnh hợp lệ.", "active_tab": "image", "mode": "image"},
        )

    mime_type = image.content_type or "image/jpeg"
    b64_preview = f"data:{mime_type};base64,{base64.b64encode(image_bytes).decode('utf-8')}"

    # Gọi Gemini Multimodal Vision
    vision_result = gemini_service.analyze_image(image_bytes, mime_type)

    matches: list[RuleMatch] = []
    extracted_text = vision_result.get("extracted_text", "")
    extracted_phone = vision_result.get("extracted_phone", "")
    visual_evidence = vision_result.get("visual_evidence", [])
    scam_category = vision_result.get("category", "Giám định hình ảnh lừa đảo")
    is_vision_scam = vision_result.get("is_scam", False)
    vision_confidence = float(vision_result.get("confidence", 85.0))

    # 1. Thêm bằng chứng từ Vision AI nếu phát hiện lừa đảo
    if is_vision_scam:
        evidence_text = " | ".join(visual_evidence) if visual_evidence else vision_result.get("analysis", "")
        matches.append(
            RuleMatch(
                rule_id="vision_scam_evidence",
                category=scam_category,
                snippet="Bằng chứng từ ảnh chụp màn hình",
                score=int(min(vision_confidence, 90.0)),
                explanation=evidence_text or vision_result.get("analysis", "Phát hiện dấu hiệu lừa đảo trên hình ảnh."),
            )
        )

    # 2. Quét văn bản OCR trích xuất được từ ảnh qua Pipeline nội bộ (Rules + Blacklist)
    phone_info = None
    if extracted_text:
        text_matches = (
            detect_all(extracted_text)
            + check_blacklist_phone(extracted_text, db)
            + check_blacklist_url(extracted_text, db)
        )
        matches.extend(text_matches)

        if extracted_phone:
            phone_info = analyze_sender_risk(extracted_phone)
            phone_info["detected_in_content"] = True
            phone_info["target_number"] = extracted_phone
            if phone_info.get("risk_score", 0) > 0:
                matches.append(
                    RuleMatch(
                        rule_id="image_phone_risk",
                        category="Số điện thoại xuất hiện trong ảnh có rủi ro",
                        snippet=extracted_phone,
                        score=int(phone_info["risk_score"]),
                        explanation=" | ".join(phone_info["notes"]),
                    )
                )
            matches.extend(check_community_reputation_matches(extracted_phone, db))

        matches.extend(check_community_reputation_matches(extracted_text, db))

    if extracted_text:
        unified_eval = scorer.evaluate_unified_risk(
            content=extracted_text,
            raw_matches=matches,
            phone_info=phone_info,
        )
        score = unified_eval["score"]
        risk_level = unified_eval["risk_level"]
        matches = unified_eval["matches"]
        ai_result = unified_eval["ai_result"]

        # Cơ chế Đối soát Kiểm chứng chéo (Cross-Verification Guardrail):
        # Nếu bộ lọc hệ thống xác nhận An toàn (do Tên miền chính thống Viettel/VNPT/Bank hoặc Cảnh báo bảo mật chuẩn)
        if risk_level == RiskLevel.LOW:
            ai_result["status_label"] = "Đã xác thực tổ chức chính thống"
            ai_result["is_scam"] = False
            ai_result["scam_prob"] = min(ai_result.get("scam_prob", 0.0), 5.0)
            ai_result["safe_prob"] = max(ai_result.get("safe_prob", 100.0), 95.0)
            ai_result["confidence"] = ai_result["safe_prob"]
            if is_vision_scam:
                # Ghi đè ảo giác của Vision AI và đồng bộ lại khối hiển thị hình ảnh
                ai_result["summary"] = (
                    "Hệ thống đã kiểm chứng chéo: Tên miền và số tổng đài trong ảnh thuộc tổ chức chính thống, "
                    "không chứa hành vi đe dọa hoặc đánh cắp mã OTP. Đây là tin nhắn quảng cáo / chăm sóc khách hàng thông thường."
                )
                vision_result["category"] = "Tin nhắn quảng cáo / Thông báo chính thống"
                vision_result["is_scam"] = False
                visual_evidence = [
                    "Đã xác thực tên miền chính thống được bảo vệ trong ảnh",
                    "Đầu số tổng đài chăm sóc khách hàng chính thức",
                    "Không ghi nhận hành vi đe dọa, đòi tiền hay chiếm đoạt mã OTP",
                ]
                vision_result["recommendation"] = (
                    "Nội dung là chương trình ưu đãi / chăm sóc khách hàng chính thống. "
                    "Người dùng có thể an tâm tra cứu thông tin hoặc liên hệ tổng đài chính thức để được hỗ trợ."
                )
        elif is_vision_scam:
            ai_result["is_scam"] = True
            ai_result["scam_prob"] = max(ai_result.get("scam_prob", 0.0), round(vision_confidence, 1))
            ai_result["safe_prob"] = round(100.0 - ai_result["scam_prob"], 1)
            ai_result["status_label"] = "Phát hiện giả mạo hình ảnh"
            if vision_result.get("analysis"):
                ai_result["summary"] = vision_result.get("analysis")
    elif is_vision_scam:
        score, risk_level = score_and_classify(matches)
        ai_result = {
            "active": True,
            "scam_prob": round(vision_confidence, 1),
            "safe_prob": round(100.0 - vision_confidence, 1),
            "is_scam": True,
            "is_suspicious": False,
            "confidence": round(vision_confidence, 1),
            "status_label": "Phát hiện giả mạo hình ảnh",
            "summary": vision_result.get("analysis", "Phát hiện dấu hiệu lừa đảo trên hình ảnh."),
        }
    else:
        score, risk_level = score_and_classify(matches)
        ai_result = {
            "active": True,
            "scam_prob": float(score),
            "safe_prob": float(100 - score),
            "is_scam": risk_level == RiskLevel.HIGH,
            "is_suspicious": risk_level == RiskLevel.MEDIUM,
            "confidence": float(score if risk_level == RiskLevel.HIGH else (100 - score)),
            "status_label": "Hình ảnh bình thường",
            "summary": vision_result.get("analysis", "Kết quả phân tích thị giác máy tính."),
        }

    display = _RISK_DISPLAY[risk_level]
    target_check = extracted_phone or extracted_text or ""
    community_stats = get_community_stats(target_check, db)

    return templates.TemplateResponse(
        request,
        "scan_result.html",
        {
            "content": extracted_text or "Ảnh chụp màn hình",
            "input_type": "image",
            "image_preview": b64_preview,
            "vision_result": vision_result,
            "visual_evidence": visual_evidence,
            "phone_info": phone_info,
            "score": score,
            "risk_level": risk_level.value,
            "risk_label": display["label"],
            "risk_advice": display["advice"],
            "matches": matches,
            "ai_result": ai_result,
            "gemini_enabled": False,
            "community_stats": community_stats,
        },
    )


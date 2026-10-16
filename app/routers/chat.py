"""
Router cho Tro ly AI Chatbot P-Sieve (Anti-Scam AI Security Assistant).
Tich hop Bo may Giam dinh Thuc dia (Scan-in-Chat), Ma tran Phan loai Nguy cap 3 Cap do (Triage Matrix),
va So tay Ung cuu Khan cap 15 Phut Vang cho Nan nhan Lua dao Truc tuyen tai Viet Nam.
"""
import os
import re
import unicodedata
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
import httpx

from app.services.gemini_service import gemini_service, GROQ_MODELS, GEMINI_MODELS
from app.detector.patterns.url_patterns import url_extractor, check_brand_impersonation
from app.detector.scorer import RiskScorer
from app.services.blacklist_service import threat_intel

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI Chatbot"])
templates = Jinja2Templates(directory="app/templates")

risk_scorer = RiskScorer()

# Danh ba Hotline 24/7 cac Ngan hang lon tai Viet Nam de khoa the / phong toa tai khoan khan cap
BANK_HOTLINES = [
    {"name": "Vietcombank", "short": "VCB", "hotline": "1900 545413", "intl": "+84 243 8243524", "action": "Bấm phím 1 để khóa thẻ khẩn cấp"},
    {"name": "Techcombank", "short": "TCB", "hotline": "1800 588822", "intl": "+84 243 9446699", "action": "Miễn cước 24/7, khóa tự động qua tổng đài"},
    {"name": "BIDV", "short": "BIDV", "hotline": "1900 9247", "intl": "+84 242 2200588", "action": "Hỗ trợ phong tỏa khẩn cấp dịch vụ SmartBanking"},
    {"name": "MBBank", "short": "MB", "hotline": "1900 545426", "intl": "+84 243 7674050", "action": "Khóa dịch vụ thẻ và e-Banking tức thời"},
    {"name": "Agribank", "short": "VBA", "hotline": "1900 558818", "intl": "+84 243 7685558", "action": "Trung tâm chăm sóc khách hàng 24/7"},
    {"name": "VietinBank", "short": "CTG", "hotline": "1900 558868", "intl": "+84 243 9418868", "action": "Phím 1 để báo mất thẻ và khóa khẩn cấp"},
    {"name": "VPBank", "short": "VPB", "hotline": "1900 545415", "intl": "+84 243 9288880", "action": "Hỗ trợ khách hàng cá nhân sự cố gian lận"},
    {"name": "ACB", "short": "ACB", "hotline": "1900 545486", "intl": "+84 283 8247247", "action": "Khóa thẻ tức thời qua tổng đài tự động"}
]

# Danh ba Co quan Quan ly Nha nuoc ve An ninh mang
CYBER_AUTHORITIES = [
    {"name": "Cục An ninh mạng và Phòng chống tội phạm CNC (A05)", "hotline": "069 2348560", "agency": "Bộ Công an"},
    {"name": "Cục Cảnh sát hình sự (C02)", "hotline": "069 2348560", "agency": "Bộ Công an"},
    {"name": "Cổng Cảnh báo An toàn thông tin Quốc gia", "hotline": "canhbao.khonggianmang.vn", "agency": "Cục An toàn thông tin"},
    {"name": "Trung tâm Ứng cứu khẩn cấp không gian mạng (VNCERT/CC)", "hotline": "086 9100311", "agency": "Bộ TT&TT"}
]

BASE_CHATBOT_INSTRUCTION = (
    "Bạn là Trợ lý AI An ninh mạng P-Sieve của Học viện Công nghệ Bưu chính Viễn thông (PTIT).\n"
    "Nhiệm vụ tối thượng: Tư vấn, vạch trần thủ đoạn lừa đảo và kích hoạt phản ứng ứng cứu khẩn cấp cho người dân tại Việt Nam "
    "(mạo danh Công an/Viện kiểm sát, tuyển CTV giật đơn thương mại điện tử, sàn chứng khoán/forex ảo, bẫy trộm OTP ngân hàng, "
    "cài file .apk mã độc chiếm quyền trợ năng Accessibility, bẫy tình cảm đầu tư Romance Scam).\n\n"
    "NGUYÊN TẮC BẮT BUỘC KHI TRẢ LỜI:\n"
    "1. Dứt khoát và rõ ràng: Khẳng định bản chất hành vi ngay từ câu đầu tiên (ví dụ: ĐÂY LÀ HÀNH VI LỪA ĐẢO 100%).\n"
    "2. Ưu tiên Quy trình 15 Phút Vàng nếu người dùng đã chuyển tiền hoặc lộ OTP: Yêu cầu khóa thẻ ngay, ngắt mạng thiết bị, thu thập bằng chứng.\n"
    "3. Giải thích vạch trần đòn tâm lý: Nêu rõ đối tượng đang thao túng nỗi sợ (án tù, vi phạm pháp luật) hay lòng tham (hoa hồng cao, tiền thưởng).\n"
    "4. Cung cấp hotline chính thống: Đưa số hotline ngân hàng hoặc số đường dây nóng A05/C02 khi cần.\n"
    "5. QUY ĐỊNH BẤT DI BẤT DỊCH: TUYỆT ĐỐI KHÔNG SỬ DỤNG BẤT KỲ ICON HOẶC EMOJI NÀO trong toàn bộ câu trả lời. Giữ văn phong an ninh mạng nghiêm túc, chuẩn mực."
)


class ChatMessage(BaseModel):
    role: str = Field(..., description="'user' hoac 'assistant'")
    content: str = Field(..., description="Noi dung tin nhan")


class ChatRequest(BaseModel):
    message: str = Field(..., description="Noi dung cau hoi / tinh huong cua nguoi dung")
    history: Optional[List[ChatMessage]] = Field(default=[], description="Lich su hoi thoai gan nhat")


def strip_accents(text: str) -> str:
    """
    Chuan hoa bo dau tieng Viet de phan tich tu khoa chinh xac ca co dau va khong dau.
    """
    normalized = unicodedata.normalize('NFD', text or "")
    stripped = re.sub(r'[\u0300-\u036f]', '', normalized)
    return stripped.replace('đ', 'd').replace('Đ', 'D').lower()


def detect_triage_level(text: str) -> Dict[str, Any]:
    """
    Ma tran Phan loai Nguy cap 3 Cap do (Incident Triage Matrix):
    - LEVEL 3 (CRITICAL): Da chuyen tien, da lo OTP, da cai file .apk
    - LEVEL 2 (WARNING): Vua bam link, da gui thong tin ca nhan, dang bi de doa
    - LEVEL 1 (INFO): Hoi thac mac, nhan dien tinh huong chung
    """
    text_raw = (text or "").lower()
    text_no_accents = strip_accents(text)

    # 1. Kiem tra Cap do 3 (CRITICAL): Tinh huong da thuc hien hanh dong nguy hiem cao
    critical_terms = [
        r"(?:da|lo|trot|vua)\s+.*?(?:chuyen\s+(?:tien|khoan)|gui\s+(?:tien|otp|ma\s+otp)|nhap\s+(?:otp|ma\s+otp|mat\s+khau)|cai\s+.*?(?:apk|app))",
        r"(?:chuyen\s+(?:tien|khoan)|nap\s+tien)\b.*?(?:roi|mat|treo|cuu\s+von)",
        r"(?:gui|nhap|doc|cung\s+cap)\s+(?:ma\s+)?otp\b",
        r"(?:da|lo|trot)\s+.*?(?:cai|tai|chay)\s+(?:file\s+)?\.?apk\b",
        r"(?:bi\s+chiem\s+quyen|bi\s+rut\s+het\s+tien|bi\s+lua\s+mat\s+tien|tai\s+khoan\s+bi\s+tru\s+tien)",
        r"(?:mat\s+tien|bi\s+tru\s+tien|bi\s+lua\s+tien)\b"
    ]
    for pattern in critical_terms:
        if re.search(pattern, text_no_accents) or re.search(pattern, text_raw):
            return {
                "level": "CRITICAL",
                "title": "BÁO ĐỘNG ĐỎ: KÍCH HOẠT QUY TRÌNH 15 PHÚT VÀNG",
                "badge": "NGUY CẤP",
                "description": "Người dùng đã thực hiện hành động rủi ro cao (chuyển tiền, gửi OTP hoặc cài tệp mã độc)."
            }

    # 2. Kiem tra Cap do 2 (WARNING): Co tuong tac nguy co
    warning_terms = [
        r"(?:vua|da|lo)\s+.*?(?:bam|an|click|vao)\s+.*?(?:link|duong\s+dan|web|trang)",
        r"(?:nhan\s+tin|chat|goi\s+dien)\s+qua\s+(?:zalo|telegram|viber)",
        r"(?:gui|chup)\s+.*?(?:cccd|cmnd)",
        r"(?:tu\s+xung|doa|yeu\s+cau)\s+(?:cong\s+an|toa\s+an|vien\s+kiem\s+sat)",
        r"(?:nhan\s+vien|cskh)\s+(?:shopee|tiki|lazada|tiktok)\s+(?:tuyen|bao\s+trung)",
        r"(?:link|trang\s+web)\s+(?:nay|do)\s+(?:co\s+an\s+toan|co\s+phai\s+lua\s+dao)"
    ]
    for pattern in warning_terms:
        if re.search(pattern, text_no_accents) or re.search(pattern, text_raw):
            return {
                "level": "WARNING",
                "title": "CẢNH BÁO NGUY CƠ: PHÒNG NGỪA RÒ RỈ DỮ LIỆU",
                "badge": "CẢNH BÁO",
                "description": "Người dùng đã tương tác với nguồn nghi vấn nhưng chưa phát sinh giao dịch tài chính hoặc mất quyền kiểm soát."
            }

    # Mac dinh Cap do 1 (INFO)
    return {
        "level": "INFO",
        "title": "TƯ VẤN & NHẬN DIỆN THỦ ĐOẠN LỪA ĐẢO",
        "badge": "TƯ VẤN",
        "description": "Tra cứu thông tin và hướng dẫn nhận diện các chiêu trò lừa đảo trực tuyến."
    }


def perform_scan_in_chat(text: str) -> Optional[Dict[str, Any]]:
    """
    Kich hoat Bo may Giam dinh P-Sieve Engine truc tiep trong cuoc hoi thoai (Scan-in-Chat).
    Trich xuat URL, kiem tra Blacklist, danh gia Typosquatting va diem rui ro ML.
    """
    urls = url_extractor.extract_urls(text)
    if not urls:
        # Neu khong co URL, kiem tra danh gia heuristic cua toan van ban
        msg_eval = risk_scorer.analyze_message(text)
        if msg_eval.get("is_scam") or msg_eval.get("risk_score", 0) > 30:
            return {
                "has_url": False,
                "target": "Văn bản hội thoại",
                "risk_score": round(float(msg_eval.get("risk_score", 0.0)), 1),
                "risk_level": msg_eval.get("risk_level", "SUSPICIOUS"),
                "is_scam": bool(msg_eval.get("is_scam")),
                "reasons": msg_eval.get("reason", [])[:3],
                "threat_type": "Ngữ nghĩa lừa đảo / Đe dọa"
            }
        return None

    primary_url = urls[0]
    eval_result = risk_scorer.analyze_message(primary_url)
    features = url_extractor.extract_features(primary_url)
    netloc = features.get("netloc", "")

    # Kiem tra blacklist danh sach den va gia mao thuong hieu
    is_safe_wl, is_blacklisted = threat_intel.check_domain_risk(netloc)
    brand_check = check_brand_impersonation(netloc)
    is_impersonation = brand_check.get("is_impersonation", False)
    brand_name = brand_check.get("brand")

    reasons = eval_result.get("reason", [])
    if is_blacklisted and "Nằm trong danh sách đen quốc gia" not in reasons:
        reasons.insert(0, "Tên miền nằm trong danh sách đen mã độc / lừa đảo")
    if is_impersonation and brand_name:
        reasons.insert(0, f"Giả mạo thương hiệu chính thống ({brand_name})")

    risk_score = float(eval_result.get("risk_score", 0.0))
    if is_blacklisted or is_impersonation:
        risk_score = max(risk_score, 95.0)

    risk_level = "HIGH" if risk_score >= 70 else ("MEDIUM" if risk_score >= 35 else "LOW")

    return {
        "has_url": True,
        "target": primary_url,
        "netloc": netloc,
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "is_scam": bool(eval_result.get("is_scam") or risk_score >= 70 or is_blacklisted or is_impersonation),
        "reasons": reasons[:4],
        "is_blacklisted": is_blacklisted,
        "impersonated_brand": brand_name if is_impersonation else None,
        "tld": features.get("tld", "")
    }


def generate_quick_actions(triage_level: str, scan_telemetry: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Tao danh sach Nut Tieu Diem Hanh Dong Nhanh phu hop voi boi canh tinh huong.
    """
    actions = []
    if triage_level == "CRITICAL":
        actions.append({"label": "Hotline Khóa Thẻ Ngân Hàng 24/7", "action": "show_bank_hotlines"})
        actions.append({"label": "Quy Trình Gỡ Bỏ File .APK Độc", "action": "show_apk_guide"})
        actions.append({"label": "Mẫu Hồ Sơ Trình Báo Công An", "action": "show_police_guide"})
    elif triage_level == "WARNING":
        actions.append({"label": "Cách Đổi Mật Khẩu & Hủy Phiên Đăng Nhập", "action": "show_security_steps"})
        actions.append({"label": "Kiểm Tra Tài Khoản Nghi Vấn", "action": "check_account_prompt"})
        actions.append({"label": "Danh Bạ Hotline Ngân Hàng", "action": "show_bank_hotlines"})
    else:
        if scan_telemetry and scan_telemetry.get("is_scam"):
            actions.append({"label": "Báo Cáo Trang Web Lừa Đảo", "action": "report_website"})
            actions.append({"label": "Hotline Ngân Hàng 24/7", "action": "show_bank_hotlines"})
        else:
            actions.append({"label": "Hotline Ngân Hàng 24/7", "action": "show_bank_hotlines"})
            actions.append({"label": "Quy Trình Ứng Cứu 15 Phút Vàng", "action": "show_golden_15m"})
            actions.append({"label": "Đường Dây Nóng An Ninh Mạng A05", "action": "show_cyber_police"})
    return actions


@router.get("/chat")
def chat_page(request: Request):
    """
    Tro ly AI Chatbot P-Sieve: Chuyen huong va tu dong kich hoat cua so Messenger Chatbot.
    """
    return RedirectResponse(url="/?open_chat=1", status_code=302)


@router.get("/api/chat/bank-hotlines")
def get_bank_hotlines():
    """
    API cung cap Danh ba Hotline 24/7 cac ngan hang lon tai Viet Nam de khoa the tuc thi.
    """
    return {
        "success": True,
        "banks": BANK_HOTLINES,
        "authorities": CYBER_AUTHORITIES
    }


@router.post("/api/chat")
def api_chat(req: ChatRequest):
    """
    API xu ly hoi dap an ninh mang tich hop:
    1. Scan-in-Chat: Giam dinh duong link va du lieu ky thuat truc tiep tu P-Sieve Engine.
    2. Incident Triage: Phan loai nguy cap 3 cap do (Do / Vang / Xanh).
    3. Groq LPU Sieu toc voi Pool ket noi ben vung, Fallback da tang bao dam 100% san sang.
    """
    user_msg = (req.message or "").strip()
    if not user_msg:
        raise HTTPException(status_code=400, detail="Nội dung câu hỏi không được để trống")

    # 1. Danh gia Ma tran Nguy cap va Giam dinh Thuc dia P-Sieve Engine
    triage = detect_triage_level(user_msg)
    scan_telemetry = perform_scan_in_chat(user_msg)
    quick_actions = generate_quick_actions(triage["level"], scan_telemetry)

    # 2. Xay dung System Prompt da bien voi Du lieu Giam dinh Thuc nghiem
    augmented_instruction = BASE_CHATBOT_INSTRUCTION + f"\n\n[CẤP ĐỘ NGUY CẤP HIỆN TẠI]: {triage['title']}"

    if scan_telemetry:
        if scan_telemetry.get("has_url"):
            augmented_instruction += (
                f"\n\n[DỮ LIỆU GIÁM ĐỊNH KỸ THUẬT P-SIEVE ENGINE]:\n"
                f"- Tên miền / URL: {scan_telemetry.get('target')}\n"
                f"- Điểm rủi ro: {scan_telemetry.get('risk_score')}/100 ({scan_telemetry.get('risk_level')})\n"
                f"- Kết luận P-Sieve: {'LỪA ĐẢO / ĐỘC HẠI' if scan_telemetry.get('is_scam') else 'ĐỘ TIN CẬY CAO / AN TOÀN'}\n"
                f"- Dấu hiệu bất thường: {'; '.join(scan_telemetry.get('reasons', []))}\n"
                f"YÊU CẦU: Hãy sử dụng chính xác các số liệu kỹ thuật thực nghiệm này để vạch trần bản chất trang web cho người dùng."
            )
        else:
            augmented_instruction += (
                f"\n\n[DỮ LIỆU ĐÁNH GIÁ TỪ P-SIEVE ENGINE]:\n"
                f"- Nội dung có dấu hiệu lừa đảo với điểm rủi ro: {scan_telemetry.get('risk_score')}/100\n"
                f"- Dấu hiệu: {'; '.join(scan_telemetry.get('reasons', []))}"
            )

    if triage["level"] == "CRITICAL":
        augmented_instruction += (
            "\n\n[HƯỚNG DẪN ĐẶC BIỆT DÀNH CHO TÌNH HUỐNG NGUY CẤP]:\n"
            "Người dùng đã chuyển tiền, lộ mã OTP hoặc cài file .apk lạ. Hãy đưa ra ngay 'QUY TRÌNH 15 PHÚT VÀNG':\n"
            "1. KHÓA TÀI KHOẢN/THẺ NGÂN HÀNG NGAY LẬP TỨC: Gọi hotline 24/7 hoặc dùng app ngân hàng bật khóa khẩn cấp.\n"
            "2. NẾU ĐÃ CÀI FILE .APK: Bật ngay Chế độ máy bay (Airplane Mode) hoặc tắt nguồn máy để ngắt điều khiển từ xa, tháo SIM sang điện thoại khác.\n"
            "3. THU THẬP BẰNG CHỨNG: Giữ nguyên lịch sử chat, sao kê biến động số dư, số tài khoản nhận tiền.\n"
            "4. BÁO CÁO CÔNG AN: Đến trực tiếp Công an phường/xã nơi gần nhất để nộp đơn tố giác tội phạm."
        )

    # 3. Chuan bi payload hoi thoai
    messages_payload = [{"role": "system", "content": augmented_instruction}]
    for h in (req.history or [])[-6:]:
        if h.role in ["user", "assistant"] and h.content.strip():
            messages_payload.append({"role": h.role, "content": h.content.strip()})
    messages_payload.append({"role": "user", "content": user_msg})

    # 4. Goi qua Groq LPU voi Persistent Client (Toc do 0.2s - 0.6s)
    groq_key = gemini_service.groq_api_key
    if groq_key:
        headers = {
            "Authorization": f"Bearer {groq_key}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 P-Sieve Security Assistant"
        }
        for model_name in GROQ_MODELS:
            payload = {
                "model": model_name,
                "messages": messages_payload,
                "temperature": 0.2,
                "max_tokens": 850
            }
            try:
                resp = gemini_service._http_client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=headers,
                    json=payload
                )
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        reply = choices[0].get("message", {}).get("content", "").strip()
                        if reply:
                            return {
                                "success": True,
                                "response": reply,
                                "triage_level": triage["level"],
                                "triage_title": triage["title"],
                                "scan_telemetry": scan_telemetry,
                                "quick_actions": quick_actions,
                                "model": model_name,
                                "provider": "Groq LPU (Siêu tốc)"
                            }
            except Exception as e:
                logger.warning(f"Groq Chatbot warning on {model_name}: {e}")

    # 5. Du phong qua Google Gemini
    gemini_key = gemini_service.api_key
    if gemini_key:
        gemini_prompt = f"{augmented_instruction}\n\nNgười dùng hỏi:\n{user_msg}"
        gemini_payload = {
            "contents": [{"parts": [{"text": gemini_prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 850
            }
        }
        for g_model in GEMINI_MODELS:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{g_model}:generateContent?key={gemini_key}"
            try:
                resp = gemini_service._http_client.post(endpoint, json=gemini_payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            reply = parts[0].get("text", "").strip()
                            if reply:
                                return {
                                    "success": True,
                                    "response": reply,
                                    "triage_level": triage["level"],
                                    "triage_title": triage["title"],
                                    "scan_telemetry": scan_telemetry,
                                    "quick_actions": quick_actions,
                                    "model": g_model,
                                    "provider": "Google Gemini"
                                }
            except Exception as e:
                logger.warning(f"Gemini Chatbot warning on {g_model}: {e}")

    # 6. Fallback Offline Thong minh tuy theo Cap do Nguy cap
    if triage["level"] == "CRITICAL":
        fallback_reply = (
            "BÁO ĐỘNG ĐỎ - KÍCH HOẠT QUY TRÌNH 15 PHÚT VÀNG:\n\n"
            "Bạn đang ở tình trạng nguy cấp do đã chuyển tiền, cung cấp mã OTP hoặc cài file mã độc. "
            "Hãy hành động ngay lập tức theo 4 bước sau:\n\n"
            "1. KHÓA TÀI KHOẢN VÀ THẺ NGÂN HÀNG NGAY:\n"
            "Gọi ngay hotline ngân hàng của bạn (Vietcombank: 1900 545413, Techcombank: 1800 588822, "
            "BIDV: 1900 9247, MBBank: 1900 545426, Agribank: 1900 558818, VietinBank: 1900 558868). "
            "Yêu cầu nhân viên phong tỏa toàn bộ tài khoản và hủy ngay phiên đăng nhập e-Banking.\n\n"
            "2. NẾU ĐÃ CÀI FILE .APK:\n"
            "Bật ngay Chế độ máy bay (Airplane Mode) hoặc tắt nguồn điện thoại. Tháo thẻ SIM sang máy khác "
            "để đối tượng không thể chặn mã OTP xác thực qua SMS.\n\n"
            "3. THU THẬP TẤT CẢ CHỨNG CỨ:\n"
            "Lưu lại số tài khoản thụ hưởng, thời gian giao dịch, mã giao dịch FT, số điện thoại đối tượng, "
            "ảnh chụp màn hình tin nhắn dụ dỗ.\n\n"
            "4. TRÌNH BÁO CƠ QUAN CÔNG AN:\n"
            "Mang toàn bộ chứng cứ tới Công an phường/xã nơi cư trú hoặc liên hệ Cục An ninh mạng A05 (069 2348560)."
        )
    elif scan_telemetry and scan_telemetry.get("is_scam"):
        fallback_reply = (
            f"KẾT QUẢ GIÁM ĐỊNH P-SIEVE: ĐÂY CHẮC CHẮN LÀ TRANG WEB LỪA ĐẢO NGUY HIỂM 100%.\n\n"
            f"- Mục tiêu giám định: {scan_telemetry.get('target')}\n"
            f"- Điểm rủi ro: {scan_telemetry.get('risk_score')}/100 (Cấp độ: {scan_telemetry.get('risk_level')})\n"
            f"- Dấu hiệu phát hiện: {'; '.join(scan_telemetry.get('reasons', []))}\n\n"
            "KHUYẾN CÁO HÀNH ĐỘNG TỨC THÌ:\n"
            "1. Đóng ngay tab trình duyệt đang mở trang web này.\n"
            "2. Tuyệt đối không nhập thông tin tài khoản, mật khẩu, số căn cước hay mã OTP.\n"
            "3. Nếu đã trót nhập thông tin, hãy đổi mật khẩu dịch vụ chính thống ngay lập tức."
        )
    else:
        fallback_reply = (
            "HỆ THỐNG AN NINH P-SIEVE KHUYẾN CÁO:\n\n"
            "- Đối tượng tự xưng Công an/Viện kiểm sát dọa bắt và yêu cầu chuyển tiền: 100% LỪA ĐẢO. "
            "Cơ quan thực thi pháp luật không bao giờ làm việc qua điện thoại hay yêu cầu chuyển tiền chứng minh.\n\n"
            "- Tuyển cộng tác viên giật đơn, like video nhận hoa hồng nạp vốn: 100% LỪA ĐẢO. "
            "Dừng ngay, tuyệt đối không nạp tiền để cứu vốn bị treo.\n\n"
            "- Mọi cuộc gọi, tin nhắn yêu cầu cung cấp mã OTP ngân hàng hoặc truy cập link nhận quà đều là bẫy lừa đảo."
        )

    return {
        "success": True,
        "response": fallback_reply,
        "triage_level": triage["level"],
        "triage_title": triage["title"],
        "scan_telemetry": scan_telemetry,
        "quick_actions": quick_actions,
        "model": "rule-based-fallback",
        "provider": "P-Sieve Offline Shield"
    }

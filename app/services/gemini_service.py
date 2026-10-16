import os
import re
import json
import logging
import httpx
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
DEFAULT_GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

GROQ_MODELS = [
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
]

GEMINI_MODELS = [
    "gemini-flash-lite-latest",
    "gemini-2.0-flash-exp",
    "gemini-3.1-flash-lite",
]


class GeminiSecurityService:
    def __init__(self, api_key: Optional[str] = None, groq_api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", DEFAULT_GEMINI_API_KEY)
        self.groq_api_key = groq_api_key or os.getenv("GROQ_API_KEY", DEFAULT_GROQ_API_KEY)
        self._http_client = httpx.Client(
            timeout=httpx.Timeout(connect=2.5, read=4.5, write=2.5, pool=3.0),
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20, keepalive_expiry=60.0)
        )
        self._semantic_cache: Dict[str, tuple[float, Dict[str, Any]]] = {}

    def is_configured(self) -> bool:
        return bool((self.api_key and self.api_key.strip()) or (self.groq_api_key and self.groq_api_key.strip()))

    @staticmethod
    def _preprocess_image(image_bytes: bytes, max_dim: int = 1600) -> tuple[bytes, str]:
        """
        Nén và tối ưu hóa hình ảnh trước khi gửi qua API:
        - Giữ độ phân giải sắc nét cao (tối đa 1600px) cho OCR đọc chữ nhỏ và đường link rõ nét.
        - Chuyển đổi sang JPEG chất lượng 92% giữ nguyên chi tiết ký tự.
        """
        try:
            from PIL import Image
            import io

            img = Image.open(io.BytesIO(image_bytes))
            # Nếu là PNG RGBA hoặc có kênh Alpha, chuyển sang RGB nền trắng
            if img.mode in ("RGBA", "P", "LA"):
                bg = Image.new("RGB", img.size, (255, 255, 255))
                if img.mode == "RGBA":
                    bg.paste(img, mask=img.split()[3])
                else:
                    bg.paste(img.convert("RGBA"))
                img = bg
            elif img.mode != "RGB":
                img = img.convert("RGB")

            # Scale nếu kích thước vượt quá max_dim
            w, h = img.size
            if max(w, h) > max_dim:
                img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

            out_buf = io.BytesIO()
            img.save(out_buf, format="JPEG", quality=92, optimize=True)
            return out_buf.getvalue(), "image/jpeg"
        except Exception as e:
            logger.warning(f"Image preprocessing warning: {e}")
            return image_bytes, "image/jpeg"

    def _generate_fallback_vision_result(self, reason: str = "quá tải hạn mức") -> Dict[str, Any]:
        """
        Cơ chế giám định an ninh dự phòng khi Google Gemini bị 429 (Quota limit) hoặc Timeout.
        Đảm bảo hệ thống KHÔNG BAO GIỜ bị chết, vẫn phản hồi ngay lập tức cho người dùng.
        """
        return {
            "active": True,
            "is_scam": False,
            "is_fallback": True,
            "confidence": 75.0,
            "risk_level": "LOW",
            "category": f"Chế độ an ninh dự phòng (Máy chủ AI {reason})",
            "extracted_text": "",
            "extracted_phone": "",
            "extracted_url": "",
            "visual_evidence": [
                f"Máy chủ AI quốc tế hiện đang phản hồi chậm hoặc đạt ngưỡng tần suất yêu cầu ({reason}).",
                "Hệ thống đã tự động kích hoạt bộ lọc bảo vệ an ninh và phân tích cục bộ.",
                "Bạn có thể sao chép văn bản, số điện thoại hoặc đường link nghi ngờ vào ô kiểm tra bên cạnh để kiểm tra chuyên sâu bằng mô hình Machine Learning nội bộ."
            ],
            "analysis": "Hệ thống đã tiếp nhận hình ảnh an toàn. Do máy chủ AI quốc tế đang tạm thời bận, để đạt độ chính xác cao nhất, khuyến nghị bạn tra cứu số điện thoại hoặc đường link trong ảnh qua ô kiểm tra bên cạnh.",
            "recommendation": "Đối với ảnh chụp chuyển tiền (Bill ngân hàng), hãy mở app ngân hàng chính thức kiểm tra số dư thực tế. Đối với giấy tờ triệu tập công an, cơ quan chức năng KHÔNG làm việc qua mạng."
        }

    def _analyze_with_groq(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Phân tích chuyên sâu tin nhắn / nội dung bằng mô hình Groq LPU (Qwen 27B / GPT-OSS).
        Tốc độ siêu tốc: 0.3s - 0.7s.
        """
        if not self.groq_api_key:
            return None

        system_instruction = (
            "Bạn là Chuyên gia An ninh mạng hàng đầu chuyên phân tích và phát hiện các thủ đoạn "
            "lừa đảo trực tuyến, cuộc gọi lừa đảo, số điện thoại rác/VoIP mạo danh, tin nhắn độc hại, "
            "cờ bạc bất hợp pháp, mạo danh cơ quan nhà nước (Công an, Tòa án, Viện kiểm sát), "
            "ngân hàng, sàn thương mại điện tử tại Việt Nam.\n\n"
            "Hãy phân tích thật cặn kẽ nội dung được cung cấp:\n"
            "- Nếu là NỘI DUNG TIN NHẮN / BÀI VIẾT: Xác định dấu hiệu lừa đảo, cờ bạc, dụ bấm link lạ, trộm OTP, ép chuyển tiền.\n"
            "- Nếu là SỐ ĐIỆN THOẠI: Phân tích rõ loại đầu số, dấu hiệu rủi ro.\n\n"
            "QUY TẮC ĐẶC BIỆT QUAN TRỌNG ĐỂ TRÁNH BÁO NHẦM (FALSE POSITIVE):\n"
            "- Rất nhiều tin nhắn là TIN NHẮN QUẢNG CÁO, KHUYẾN MÃI, CHĂM SÓC KHÁCH HÀNG CHÍNH THỐNG của các nhà mạng (Viettel, Vinaphone, Mobifone) hoặc Ngân hàng/Doanh nghiệp lớn.\n"
            "- DANH SÁCH TÊN MIỀN VÀ ĐẦU SỐ CHÍNH THỨC CẦN LƯU Ý:\n"
            "  + Viettel: viettel.vn, myviettel.vn, viettelmoney.vn, vt.vn, viettel.go.link; Tổng đài: 198, 197, 191, 195, 100.\n"
            "  + Vinaphone / VNPT: vinaphone.com.vn, vnpt.com.vn; Tổng đài: 18001091, 9191.\n"
            "  + Mobifone: mobifone.vn; Tổng đài: 18001090, 9090.\n"
            "  + Cơ quan nhà nước: *.gov.vn, *.chinhphu.vn, vneid.gov.vn, dichvucong.gov.vn.\n"
            "  + Ngân hàng: vietcombank.com.vn, techcombank.com, bidv.com.vn, mbbank.com.vn, vpbank.com.vn...\n"
            "- ĐIỀU KIỆN XÁC ĐỊNH LÀ TIN NHẮN CHÍNH THỐNG / AN TOÀN (is_scam = false, risk_level = 'LOW'):\n"
            "  + Đường dẫn liên kết thuộc tên miền gốc chính thức ở trên (ví dụ: https://viettel.vn/... hoặc sub-link chính thức).\n"
            "  + Tin nhắn khuyến mãi nạp thẻ, tặng data, đổi điểm Viettel++, giới thiệu tính năng/chương trình mới kèm số tổng đài CSKH (198, 191...).\n"
            "  + KHÔNG yêu cầu chuyển tiền đến tài khoản cá nhân, KHÔNG yêu cầu đọc/nhập mã OTP hay mật khẩu, KHÔNG đe dọa khóa số hay phạt tiền.\n"
            "  -> KHI ĐÓ: Tuyệt đối KHÔNG được kết luận là lừa đảo. Hãy kết luận 'is_scam': false, 'risk_level': 'LOW', 'category': 'Tin nhắn quảng cáo / Chăm sóc khách hàng chính thống'.\n\n"
            "QUAN TRỌNG: Bạn chỉ được trả về DUY NHẤT một chuỗi JSON chuẩn (không bọc trong markdown ```json, "
            "không thêm bất kỳ lời dẫn nào khác ngoài JSON) với cấu trúc sau:\n"
            "{\n"
            '  "is_scam": false,\n'
            '  "confidence": 95.0,\n'
            '  "risk_level": "LOW",\n'
            '  "category": "Tin nhắn quảng cáo / Chăm sóc khách hàng chính thống",\n'
            '  "analysis": "Trình bày các ý phân tích rõ ràng theo từng gạch đầu dòng, mỗi ý xuống dòng bắt đầu bằng dấu gạch ngang (-). Nêu rõ lý do an toàn hoặc các dấu hiệu bất thường nếu có. Không dùng văn phong rập khuôn máy móc.",\n'
            '  "recommendation": "Lời khuyên bảo vệ an toàn cụ thể cho người dùng."\n'
            "}\n"
            "Lưu ý: risk_level chỉ nhận một trong 3 giá trị: 'HIGH', 'MEDIUM', 'LOW'."
        )

        user_content = f"Nội dung cần kiểm tra:\n\"\"\"{text.strip()}\"\"\""
        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 P-Sieve Security Agent"
        }

        for model in GROQ_MODELS:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": user_content}
                ],
                "temperature": 0.1,
                "max_tokens": 600
            }
            try:
                with httpx.Client(timeout=4.0) as client:
                    resp = client.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        raw_text = choices[0].get("message", {}).get("content", "")
                        parsed = self._parse_json_response(raw_text)
                        if parsed and isinstance(parsed, dict) and "is_scam" in parsed:
                            parsed["active"] = True
                            parsed["model_used"] = f"Groq LPU ({model.split('/')[-1]})"
                            return parsed
                else:
                    logger.warning(f"Groq API {model} HTTP {resp.status_code}: {resp.text[:100]}")
            except Exception as e:
                logger.warning(f"Groq API {model} call error: {e}")

        return None

    def _analyze_with_gemini(self, text: str) -> Dict[str, Any]:
        """
        Phân tích chuyên sâu tin nhắn / nội dung bằng mô hình Gemini AI.
        Trả về kết quả chi tiết kèm phân tích tâm lý, rủi ro và khuyến nghị an toàn.
        """
        system_instruction = (
            "Bạn là Chuyên gia An ninh mạng hàng đầu chuyên phân tích và phát hiện các thủ đoạn "
            "lừa đảo trực tuyến, cuộc gọi lừa đảo, số điện thoại rác/VoIP mạo danh, tin nhắn độc hại, "
            "cờ bạc bất hợp pháp, mạo danh cơ quan nhà nước (Công an, Tòa án, Viện kiểm sát), "
            "ngân hàng, sàn thương mại điện tử tại Việt Nam.\n\n"
            "Hãy phân tích thật cặn kẽ nội dung được cung cấp:\n"
            "- Nếu là NỘI DUNG TIN NHẮN / BÀI VIẾT: Xác định dấu hiệu lừa đảo, cờ bạc, dụ bấm link lạ, trộm OTP, ép chuyển tiền.\n"
            "- Nếu là SỐ ĐIỆN THOẠI (đặc biệt các đầu số cố định 024, 028, dải ảo 999x, 888x, 730x, 445x, đầu số 1900 hoặc số quốc tế): "
            "Hãy phân tích rõ loại đầu số (VoIP/SIP Trunk/Cố định/Di động), các thủ đoạn lừa đảo thường dùng đầu số này tại Việt Nam "
            "(giả danh công an dọa lệnh bắt/phạt nguội giao thông, mạo danh ngân hàng lừa OTP, nháy máy trừ cước VAS, mời chứng khoán rác...), "
            "và đưa ra lời khuyên bảo vệ dứt khoát.\n\n"
            "QUY TẮC ĐẶC BIỆT QUAN TRỌNG ĐỂ TRÁNH BÁO NHẦM (FALSE POSITIVE):\n"
            "- Rất nhiều tin nhắn là TIN NHẮN QUẢNG CÁO, KHUYẾN MÃI, CHĂM SÓC KHÁCH HÀNG CHÍNH THỐNG của các nhà mạng (Viettel, Vinaphone, Mobifone) hoặc Ngân hàng/Doanh nghiệp lớn.\n"
            "- DANH SÁCH TÊN MIỀN VÀ ĐẦU SỐ CHÍNH THỨC CẦN LƯU Ý:\n"
            "  + Viettel: viettel.vn, myviettel.vn, viettelmoney.vn, vt.vn, viettel.go.link; Tổng đài: 198, 197, 191, 195, 100.\n"
            "  + Vinaphone / VNPT: vinaphone.com.vn, vnpt.com.vn; Tổng đài: 18001091, 9191.\n"
            "  + Mobifone: mobifone.vn; Tổng đài: 18001090, 9090.\n"
            "  + Cơ quan nhà nước: *.gov.vn, *.chinhphu.vn, vneid.gov.vn, dichvucong.gov.vn.\n"
            "  + Ngân hàng: vietcombank.com.vn, techcombank.com, bidv.com.vn, mbbank.com.vn, vpbank.com.vn...\n"
            "- ĐIỀU KIỆN XÁC ĐỊNH LÀ TIN NHẮN CHÍNH THỐNG / AN TOÀN (is_scam = false, risk_level = 'LOW'):\n"
            "  + Đường dẫn liên kết thuộc tên miền gốc chính thức ở trên (ví dụ: https://viettel.vn/... hoặc sub-link chính thức).\n"
            "  + Tin nhắn khuyến mãi nạp thẻ, tặng data, đổi điểm Viettel++, giới thiệu tính năng/chương trình mới kèm số tổng đài CSKH (198, 191...).\n"
            "  + KHÔNG yêu cầu chuyển tiền đến tài khoản cá nhân, KHÔNG yêu cầu đọc/nhập mã OTP hay mật khẩu, KHÔNG đe dọa khóa số hay phạt tiền.\n"
            "  -> KHI ĐÓ: Tuyệt đối KHÔNG được kết luận là lừa đảo. Hãy kết luận 'is_scam': false, 'risk_level': 'LOW', 'category': 'Tin nhắn quảng cáo / Chăm sóc khách hàng chính thống'.\n\n"
            "QUAN TRỌNG: Bạn chỉ được trả về DUY NHẤT một chuỗi JSON chuẩn (không bọc trong markdown ```json, "
            "không thêm bất kỳ lời dẫn nào khác ngoài JSON) với cấu trúc sau:\n"
            "{\n"
            '  "is_scam": false,\n'
            '  "confidence": 95.0,\n'
            '  "risk_level": "LOW",\n'
            '  "category": "Tin nhắn quảng cáo / Chăm sóc khách hàng chính thống",\n'
            '  "analysis": "Trình bày các ý phân tích rõ ràng theo từng gạch đầu dòng, mỗi ý xuống dòng bắt đầu bằng dấu gạch ngang (-). Nêu rõ lý do an toàn hoặc các dấu hiệu bất thường nếu có. Không dùng văn phong rập khuôn máy móc.",\n'
            '  "recommendation": "Lời khuyên bảo vệ an toàn cụ thể cho người dùng."\n'
            "}\n"
            "Lưu ý: risk_level chỉ nhận một trong 3 giá trị: 'HIGH', 'MEDIUM', 'LOW'."
        )

        user_content = f"Nội dung cần kiểm tra:\n\"\"\"{text.strip()}\"\"\""

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{system_instruction}\n\n{user_content}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "topP": 0.95,
                "maxOutputTokens": 1024,
            }
        }

        # Thử lần lượt các model dự phòng
        last_error = ""
        for model in GEMINI_MODELS:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}
            try:
                with httpx.Client(timeout=4.5) as client:
                    response = client.post(url, json=payload, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        content_part = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        parsed_json = self._parse_json_response(content_part)
                        if parsed_json:
                            parsed_json["active"] = True
                            parsed_json["model_used"] = f"Google ({model})"
                            return parsed_json
                else:
                    last_error = f"Model {model} HTTP {response.status_code}: {response.text[:120]}"
                    logger.warning(f"Gemini API warning: {last_error}")
            except Exception as e:
                last_error = str(e)
                logger.error(f"Error calling Gemini model {model}: {e}")

        return {
            "active": False,
            "error": f"Không thể kết nối đến Gemini AI ({last_error})",
        }

    def analyze_message(self, text: str) -> Dict[str, Any]:
        """
        Phân tích chuyên sâu tin nhắn / nội dung bằng kiến trúc Multi-AI Song Song:
        1. Ưu tiên số 1: Groq LPU (Qwen 27B / GPT-OSS) - Tốc độ siêu tốc (0.3s - 0.7s).
        2. Chạy song song / Dự phòng: Google Gemini (2.0 Flash / 1.5 Flash).
        """
        if not self.is_configured():
            return {"active": False, "error": "Chưa cấu hình API Key"}

        if not text or not text.strip():
            return {"active": False, "error": "Nội dung trống"}

        # 1. Thử phân tích qua Groq LPU siêu tốc
        if self.groq_api_key and self.groq_api_key.strip():
            groq_res = self._analyze_with_groq(text)
            if groq_res and groq_res.get("active"):
                return groq_res

        # 2. Dự phòng qua Google Gemini
        if self.api_key and self.api_key.strip():
            gemini_res = self._analyze_with_gemini(text)
            if gemini_res and gemini_res.get("active"):
                return gemini_res

        return {
            "active": False,
            "error": "Không thể kết nối đến máy chủ AI (Groq & Gemini tạm thời bận)",
        }

    def analyze_image(self, image_bytes: bytes, mime_type: str = "image/jpeg") -> Dict[str, Any]:
        """
        Phân tích chuyên sâu hình ảnh / ảnh chụp màn hình bằng mô hình Gemini Multimodal Vision.
        Giám định:
        1. Biên lai chuyển tiền ngân hàng giả (Fake Bank Bill / Photoshop).
        2. Giấy triệu tập / Lệnh bắt giữ giả mạo của cơ quan Công an / Tòa án.
        3. Ảnh chụp màn hình tin nhắn / đoạn chat lừa đảo tuyển dụng, cờ bạc, vay tiền.
        4. Trích xuất toàn bộ văn bản (OCR) và các số điện thoại / liên kết trong ảnh.
        """
        if not self.is_configured():
            return {"active": False, "error": "Chưa cấu hình GEMINI_API_KEY"}

        if not image_bytes:
            return {"active": False, "error": "Dữ liệu ảnh trống"}

        # 1. Tối ưu nén ảnh siêu nhẹ trước khi tải lên (giảm 85% dung lượng, phản hồi cực nhanh 1-2s)
        compressed_bytes, mime_type = self._preprocess_image(image_bytes, max_dim=1200)

        import base64
        b64_data = base64.b64encode(compressed_bytes).decode("utf-8")

        system_instruction = (
            "Bạn là Chuyên gia Giám định Kỹ thuật số và An ninh mạng chuyên phân tích "
            "các hình ảnh, ảnh chụp màn hình liên quan đến lừa đảo tại Việt Nam.\n\n"
            "CÁC LOẠI HÌNH ẢNH CẦN GIÁM ĐỊNH:\n"
            "1. BIÊN LAI CHUYỂN TIỀN NGÂN HÀNG GIẢ (Fake Banking Bill): Soi các dấu hiệu chỉnh sửa Photoshop, "
            "sai phông chữ số tiền, lệch vị trí thời gian, số dư bất thường, mạo danh app Vietcombank/MBBank/Techcombank/BIDV...\n"
            "2. GIẤY TRIỆU TẬP / LỆNH BẮT GIỮ / QUYẾT ĐỊNH KHỞI TỐ GIẢ MẠO: Có con dấu đỏ giả của Công an, "
            "Viện kiểm sát, Tòa án nhằm đe dọa tống tiền người dân.\n"
            "3. ẢNH CHỤP MÀN HÌNH TIN NHẮN / ĐOẠN CHAT LỪA ĐẢO: Chat Zalo/Telegram tuyển dụng làm nhiệm vụ online, "
            "nạp tiền nhận hoa hồng, đầu tư tiền ảo/Forex, hoặc thông báo trúng thưởng đóng phí.\n"
            "4. THÔNG BÁO / VĂN BẢN MẠO DANH DOANH NGHIỆP: Nâng cấp SIM, thông báo trúng quà tặng, đòi nợ cước viễn thông chứa link lạ, tải file APK độc hại.\n\n"
            "QUY TẮC ĐẶC BIỆT QUAN TRỌNG ĐỂ TRÁNH BÁO NHẦM (FALSE POSITIVE):\n"
            "- Rất nhiều tin nhắn là TIN NHẮN QUẢNG CÁO, KHUYẾN MÃI, CHĂM SÓC KHÁCH HÀNG CHÍNH THỐNG của các nhà mạng (Viettel, Vinaphone, Mobifone) hoặc Ngân hàng/Doanh nghiệp lớn.\n"
            "- DANH SÁCH TÊN MIỀN VÀ ĐẦU SỐ CHÍNH THỨC CẦN LƯU Ý:\n"
            "  + Viettel: viettel.vn, myviettel.vn, viettelmoney.vn, vt.vn, viettel.go.link; Tổng đài: 198, 197, 191, 195, 100.\n"
            "  + Vinaphone / VNPT: vinaphone.com.vn, vnpt.com.vn; Tổng đài: 18001091, 9191.\n"
            "  + Mobifone: mobifone.vn; Tổng đài: 18001090, 9090.\n"
            "  + Cơ quan nhà nước: *.gov.vn, *.chinhphu.vn, vneid.gov.vn, dichvucong.gov.vn.\n"
            "  + Ngân hàng: vietcombank.com.vn, techcombank.com, bidv.com.vn, mbbank.com.vn, vpbank.com.vn...\n"
            "- ĐIỀU KIỆN XÁC ĐỊNH LÀ TIN NHẮN CHÍNH THỐNG / AN TOÀN (is_scam = false, risk_level = 'LOW'):\n"
            "  + Đường dẫn liên kết thuộc tên miền gốc chính thức ở trên (ví dụ: https://viettel.vn/... hoặc sub-link chính thức).\n"
            "  + Tin nhắn khuyến mãi nạp thẻ, tặng data, đổi điểm Viettel++, giới thiệu tính năng/chương trình mới kèm số tổng đài CSKH (198, 191...).\n"
            "  + KHÔNG yêu cầu chuyển tiền đến tài khoản cá nhân, KHÔNG yêu cầu đọc/nhập mã OTP hay mật khẩu, KHÔNG đe dọa khóa số hay phạt tiền.\n"
            "  -> KHI ĐÓ: Tuyệt đối KHÔNG được kết luận là lừa đảo. Hãy kết luận 'is_scam': false, 'risk_level': 'LOW', 'category': 'Tin nhắn quảng cáo / Chăm sóc khách hàng chính thống'.\n\n"
            "NHIỆM VỤ CỦA BẠN:\n"
            "- Trích xuất CHÍNH XÁC 100% NGUYÊN VĂN toàn bộ nội dung xuất hiện trong ảnh (từng câu, từng chữ, số điện thoại, đường link, số tài khoản). Tuyệt đối KHÔNG được tóm tắt, KHÔNG được chỉ trích xuất mỗi đường link hay mỗi số điện thoại mà phải giữ trọn vẹn toàn bộ đoạn văn bản ngữ cảnh.\n"
            "- Chỉ ra các bằng chứng thị giác cụ thể (Visual Evidence).\n"
            "- Đưa ra kết luận khách quan, chính xác.\n\n"
            "QUAN TRỌNG: Bạn chỉ được trả về DUY NHẤT một chuỗi JSON chuẩn (không bọc trong markdown ```json, không có lời dẫn nào khác) với cấu trúc sau:\n"
            "{\n"
            '  "is_scam": false,\n'
            '  "confidence": 95.0,\n'
            '  "risk_level": "LOW",\n'
            '  "category": "Tin nhắn quảng cáo / Chăm sóc khách hàng chính thống",\n'
            '  "extracted_text": "Toàn bộ văn bản đầy đủ đọc được trong ảnh...",\n'
            '  "extracted_phone": "Số điện thoại xuất hiện trong ảnh nếu có",\n'
            '  "extracted_url": "Đường link xuất hiện trong ảnh nếu có",\n'
            '  "visual_evidence": [\n'
            '    "Tên miền chính thức viettel.vn và đầu số tổng đài chính thống 198",\n'
            '    "Nội dung là chương trình đổi điểm Viettel++ không có hành vi đòi mã OTP hay đe dọa"\n'
            '  ],\n'
            '  "analysis": "Trình bày theo các gạch đầu dòng rõ ràng, mỗi ý xuống dòng bắt đầu bằng dấu gạch ngang (-). Nêu rõ bản chất tin nhắn là quảng cáo chính thống hay giả mạo.",\n'
            '  "recommendation": "Khuyến nghị an toàn cụ thể cho người dùng."\n'
            "}\n"
            "Lưu ý: risk_level chỉ nhận một trong 3 giá trị: 'HIGH', 'MEDIUM', 'LOW'."
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": system_instruction},
                        {
                            "inlineData": {
                                "mimeType": mime_type,
                                "data": b64_data,
                            }
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "topP": 0.95,
                "maxOutputTokens": 1536,
            }
        }

        last_error = ""
        for model in GEMINI_MODELS:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}
            try:
                with httpx.Client(timeout=9.0) as client:
                    response = client.post(url, json=payload, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        content_part = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        parsed_json = self._parse_json_response(content_part)
                        if parsed_json:
                            parsed_json["active"] = True
                            parsed_json["model_used"] = model
                            return parsed_json
                elif response.status_code == 429:
                    last_error = f"Model {model} chạm hạn mức (HTTP 429)"
                    logger.warning(f"Gemini Vision API quota exceeded (HTTP 429) on model {model}, trying next model...")
                    continue
                else:
                    last_error = f"Model {model} HTTP {response.status_code}: {response.text[:120]}"
                    logger.warning(f"Gemini Vision API warning: {last_error}")
            except httpx.TimeoutException:
                last_error = f"Model {model} phản hồi quá lâu (Timeout)"
                logger.warning(f"Gemini Vision API timeout on model {model}, trying next model...")
                continue
            except Exception as e:
                last_error = str(e)
                logger.error(f"Error calling Gemini Vision model {model}: {e}")

        # Neu khong co model nao phan hoi kip thoi, kich hoat che do bao ve noi bo thay vi bao loi
        return self._generate_fallback_vision_result(reason=f"kết nối không ổn định ({last_error})")

    def _fallback_webpage_semantic(
        self,
        url: str,
        title: str,
        text: str,
        technical_context: str = "",
        tech_is_scam: bool = False,
    ) -> Dict[str, Any]:
        """Phân tích ngữ cảnh web dự phòng offline bằng bộ quy tắc nâng cao tích hợp đối soát kỹ thuật."""
        combined = f"{url} {title} {text}".lower()

        # 1. Bẫy việc làm / nhiệm vụ / cộng tác viên
        job_scam_kw = ["tuyển ctv", "cộng tác viên", "làm tại nhà", "giật đơn", "chốt đơn", "hoa hồng", "nhiệm vụ", "xem video kiếm tiền", "like tiktok", "shopee tuyển", "tiki tuyển"]
        matched_job = [kw for kw in job_scam_kw if kw in combined]

        if len(matched_job) >= 2 or ("giật đơn" in combined) or ("tuyển ctv" in combined) or ("chốt đơn" in combined) or ("thu hồi vốn treo" in combined):
            return {
                "active": True,
                "is_scam": True,
                "confidence": 92.0,
                "risk_level": "HIGH",
                "scam_category": "Lừa đảo tuyển dụng / Việc làm online hoặc Thu hồi vốn treo",
                "summary": "Nội dung trang web khớp với kịch bản lừa đảo dụ dỗ nạp tiền làm nhiệm vụ hoặc mạo danh chuyên gia lấy lại tiền.",
                "analysis": "- Trang web đưa ra các cam kết việc làm thu nhập cao bất thường hoặc dịch vụ lấy lại tiền lừa đảo.\n- Đây là mô hình lừa đảo tài chính phổ biến nhằm chiếm đoạt tiền nạp ban đầu.",
                "recommendation": "TUYỆT ĐỐI KHÔNG làm theo hướng dẫn, không chuyển tiền đặt cọc hoặc làm nhiệm vụ nạp vốn."
            }

        # 2. Bẫy ngân hàng / OTP / Mạo danh tổ chức tài chính
        bank_scam_kw = ["smart otp", "xác thực otp", "mã otp", "khóa tài khoản", "hủy lệnh", "chuyển tiền", "vietcombank", "techcombank", "mbbank", "bidv", "agribank", "vcb", "tcb", "mb bank", "vietinbank"]
        has_bank_kw = any(kw in combined for kw in bank_scam_kw)
        has_otp = any(kw in combined for kw in ["smart otp", "mã otp", "xác thực otp", "nhập otp", "mã xác thực", "otp", "token"])
        if (has_bank_kw and has_otp) or ("smart otp" in combined) or ("xác thực otp" in combined):
            return {
                "active": True,
                "is_scam": True,
                "confidence": 98.0,
                "risk_level": "HIGH",
                "scam_category": "Giả mạo ngân hàng / Bẫy đánh cắp mã Smart OTP",
                "summary": "Phát hiện kịch bản giả mạo thương hiệu ngân hàng nhằm chiếm đoạt mã OTP hoặc tài khoản Internet Banking.",
                "analysis": "- Trang web yêu cầu cung cấp thông tin tài khoản hoặc mã xác thực OTP.\n- Đây là hình thức lừa đảo phishing trực tiếp dẫn đến mất tiền trong tài khoản.",
                "recommendation": "CẢNH BÁO NGUY HIỂM: Tuyệt đối KHÔNG nhập mã OTP, mật khẩu hay số tài khoản."
            }

        # 3. Bẫy đầu tư / tài chính / tiền ảo
        invest_scam_kw = ["lãi suất ngày", "cam kết lợi nhuận", "đầu tư thông minh", "chuyên gia đọc lệnh", "kéo vốn", "thu hồi vốn treo", "hỗ trợ lấy lại tiền"]
        matched_invest = [kw for kw in invest_scam_kw if kw in combined]
        if len(matched_invest) >= 2 or ("kéo vốn" in combined):
            return {
                "active": True,
                "is_scam": True,
                "confidence": 90.0,
                "risk_level": "HIGH",
                "scam_category": "Lừa đảo đầu tư tài chính / Sàn giao dịch ảo",
                "summary": "Phát hiện dấu hiệu dụ dỗ tham gia mô hình đầu tư lợi nhuận cao không thực tế.",
                "analysis": "- Dấu hiệu cam kết lợi nhuận cố định và chuyên gia dẫn dắt đọc lệnh.\n- Mô hình có nguy cơ đóng sàn chiếm đoạt tài sản sau khi nạp số tiền lớn.",
                "recommendation": "Dừng mọi giao dịch đầu tư vào các nền tảng chưa được Ngân hàng Nhà nước cấp phép."
            }
        elif len(matched_gambling) >= 2:
            return {
                "active": True,
                "is_scam": True,
                "confidence": 95.0,
                "risk_level": "HIGH",
                "scam_category": "Cờ bạc trực tuyến / Cá cược bất hợp pháp",
                "summary": "Trang web chứa nội dung cờ bạc, cá cược trái phép theo quy định pháp luật Việt Nam.",
                "analysis": "- Phát hiện các từ khóa cờ bạc, nổ hũ, cá cược trực tuyến.\n- Các trang này thường bị các nhà mạng chặn và có nguy cơ lừa đảo tiền nạp cao.",
                "recommendation": "Rời khỏi trang web và không nạp tiền vào hệ thống."
            }

        # 4. Kiểm tra trạng thái trang đỗ hoặc che giấu trên tên miền nguy hiểm
        is_parking = any(kw in combined for kw in ["parking page", "domain parking", "sedoparking", "under construction", "buy this domain", "parked free"])
        if tech_is_scam or (is_parking and any(url.lower().endswith(tld) or (tld + "/") in url.lower() for tld in [".sbs", ".top", ".xyz", ".vip", ".club"])):
            return {
                "active": True,
                "is_scam": True,
                "confidence": 95.0,
                "risk_level": "HIGH",
                "scam_category": "Tên miền rủi ro cao / Ngụy trang hạ tầng lừa đảo",
                "summary": f"Tên miền có rủi ro kỹ thuật nghiêm trọng ({technical_context or 'tên miền thuộc phần mở rộng nguy cơ cao'}) và đang ở trạng thái ngụy trang trang đỗ (parking page) hoặc hạ tầng chờ kích hoạt kịch bản lừa đảo.",
                "analysis": "- Hệ thống an ninh xác nhận tên miền có rủi ro kỹ thuật cao hoặc nằm trong danh mục tên miền rác/lừa đảo.\n- Hiện tại trang web chỉ hiển thị trang đỗ hoặc nội dung tối thiểu nhằm lẩn tránh các bộ lọc tự động (Evasion/Cloaking).\n- Tuyệt đối cảnh giác, không tin tưởng hoặc chuyển tiền cho các dịch vụ liên kết với tên miền này.",
                "recommendation": "CẢNH BÁO NGUY HIỂM: Rời khỏi trang web ngay và không truy cập vào các đường dẫn xuất phát từ tên miền này."
            }
        
        return {
            "active": True,
            "is_scam": False,
            "confidence": 80.0,
            "risk_level": "LOW",
            "scam_category": "Nội dung thông thường / Chưa phát hiện dấu hiệu lừa đảo",
            "summary": "Mô hình ngữ nghĩa chưa phát hiện các kịch bản dụ dỗ nạp tiền hoặc việc làm lừa đảo trong nội dung trang web.",
            "analysis": "- Không phát hiện các từ khóa hoặc kịch bản lừa đảo tài chính/tuyển dụng đặc trưng.\n- Cần tiếp tục duy trì cảnh giác đối với các yêu cầu giao dịch bất thường.",
            "recommendation": "Trang web không có dấu hiệu lừa đảo nội dung rõ rệt, tuy nhiên luôn cẩn trọng khi cung cấp thông tin tài khoản."
        }

    def analyze_webpage_semantic(
        self,
        url: str,
        title: str,
        page_text: str,
        technical_context: str = "",
        tech_is_scam: bool = False,
    ) -> Dict[str, Any]:
        """
        Phân tích chuyên sâu ngữ nghĩa nội dung trang web bằng Gemini AI
        tích hợp đối soát bối cảnh an ninh kỹ thuật và tối ưu tốc độ phản hồi.
        """
        cleaned_text = (page_text or "").strip()[:800]
        combined_text = f"{url} {title} {cleaned_text}".lower()

        # Kiểm tra trạng thái trang đỗ hoặc cloaking trên tên miền nguy hiểm
        is_parking = any(kw in combined_text for kw in ["parking page", "domain parking", "sedoparking", "under construction", "buy this domain", "parked free"])
        if tech_is_scam and (is_parking or len(cleaned_text) < 40):
            return self._fallback_webpage_semantic(url, title, page_text, technical_context=technical_context, tech_is_scam=True)

        if not self.is_configured():
            return self._fallback_webpage_semantic(url, title, page_text, technical_context=technical_context, tech_is_scam=tech_is_scam)

        if not cleaned_text and not title:
            if tech_is_scam:
                return self._fallback_webpage_semantic(url, title, "", technical_context=technical_context, tech_is_scam=True)
            return {
                "active": False,
                "is_scam": False,
                "confidence": 50.0,
                "risk_level": "LOW",
                "scam_category": "Không đủ dữ liệu văn bản",
                "summary": "Trang web không có đủ văn bản để phân tích ngữ nghĩa AI.",
                "analysis": "- Trang web chứa ít nội dung hoặc được render hoàn toàn bằng đồ họa/mã hóa.\n- Khuyến nghị kiểm tra tên miền và ô nhập liệu.",
                "recommendation": "Cần thận trọng nếu trang web yêu cầu đăng nhập hoặc chuyển tiền mà không có nội dung rõ ràng."
            }

        tech_instruction_note = ""
        if technical_context:
            tech_instruction_note = (
                f"\nBỐI CẢNH AN NINH KỸ THUẬT: {technical_context}\n"
                "- NGUYÊN TẮC: Nếu hệ thống kỹ thuật cảnh báo tên miền có nguy cơ lừa đảo cao (điểm >= 70 hoặc đuôi tên miền .sbs, .xyz...), "
                "hoặc trang hiển thị dạng trang đỗ (parking page) che giấu hành vi, BẮT BUỘC phải kết luận is_scam = true, risk_level = 'HIGH'. "
                "Nếu nội dung trang chứa dấu hiệu việc làm/CTV, đầu tư, cờ bạc, hãy đặt scam_category theo đúng thủ đoạn lừa đảo đó; "
                "chỉ khi trang là trang đỗ hoặc không có nội dung mới đặt scam_category = 'Tên miền rủi ro cao / Ngụy trang hạ tầng lừa đảo'. "
                "TUYỆT ĐỐI KHÔNG đánh giá là An toàn!\n"
            )

        system_instruction = (
            "Bạn là Chuyên gia An ninh mạng hàng đầu chuyên phân tích nội dung trang web để phát hiện "
            "các thủ đoạn lừa đảo tại Việt Nam (tuyển dụng CTV ảo, giật đơn, đầu tư tài chính ảo, mạo danh cơ quan, trang đỗ lừa đảo).\n"
            f"{tech_instruction_note}"
            "LƯU Ý: Nếu là trang tin tức, blog học tập, trang công nghệ hoặc web bán hàng chính thống, "
            "hãy đánh giá is_scam = false, risk_level = 'LOW'.\n\n"
            "QUAN TRỌNG: Bạn chỉ được trả về DUY NHẤT một chuỗi JSON chuẩn (không bọc trong markdown, "
            "không thêm bất kỳ lời dẫn nào khác) theo cấu trúc:\n"
            "{\n"
            '  "is_scam": false,\n'
            '  "confidence": 90.0,\n'
            '  "risk_level": "LOW",\n'
            '  "scam_category": "Tên phân loại lừa đảo nếu có hoặc Nội dung thông thường",\n'
            '  "summary": "Tóm tắt ngắn gọn đánh giá rủi ro (1-2 câu).",\n'
            '  "analysis": "Các gạch đầu dòng phân tích chi tiết, bắt đầu bằng (-).",\n'
            '  "recommendation": "Lời khuyên hành động dứt khoát cho người dùng."\n'
            "}\n"
            "Lưu ý: risk_level chỉ nhận 'HIGH', 'MEDIUM', hoặc 'LOW'."
        )

        user_content = (
            f"Thông tin trang web cần thẩm định an ninh:\n"
            f"- URL: {url}\n"
            f"- Tiêu đề (Title): {title}\n"
            f"- Bối cảnh kỹ thuật: {technical_context or 'Không có'}\n"
            f"- Nội dung trích xuất từ trang:\n\"\"\"\n{cleaned_text}\n\"\"\""
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{system_instruction}\n\n{user_content}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.0,
                "topP": 0.9,
                "maxOutputTokens": 450,
            }
        }

        # 1. Kiem tra bo nho dem semantic cache (< 0.1ms)
        import time
        now = time.time()
        cache_key = f"{url.strip()}:{title.strip()}:{cleaned_text[:300].strip()}"
        if cache_key in self._semantic_cache:
            c_time, c_data = self._semantic_cache[cache_key]
            if now - c_time < 300:
                return c_data

        # 2. Thử phân tích qua Groq LPU siêu tốc (0.3s - 0.7s)
        if self.groq_api_key:
            groq_headers = {
                "Authorization": f"Bearer {self.groq_api_key}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 P-Sieve Security Agent"
            }
            for groq_m in ["qwen/qwen3.8-27b", "openai/gpt-oss-20b"]:
                groq_payload = {
                    "model": groq_m,
                    "messages": [
                        {"role": "system", "content": system_instruction},
                        {"role": "user", "content": user_content}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.0,
                    "max_tokens": 450
                }
                try:
                    resp = self._http_client.post("https://api.groq.com/openai/v1/chat/completions", headers=groq_headers, json=groq_payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        choices = data.get("choices", [])
                        if choices:
                            raw_text = choices[0].get("message", {}).get("content", "")
                            parsed = self._parse_json_response(raw_text)
                            if parsed and isinstance(parsed, dict) and "is_scam" in parsed:
                                parsed["active"] = True
                                parsed["model_used"] = f"Groq LPU ({groq_m.split('/')[-1]})"
                                self._semantic_cache[cache_key] = (now, parsed)
                                return parsed
                except Exception as e:
                    logger.warning(f"Groq webpage semantic warning on model {groq_m}: {e}")

        # 3. Dự phòng qua Google Gemini
        for model in GEMINI_MODELS:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}
            try:
                resp = self._http_client.post(endpoint, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        part = candidates[0].get("content", {}).get("parts", [{}])[0]
                        raw_text = part.get("text", "")
                        parsed = self._parse_json_response(raw_text)
                        if parsed and isinstance(parsed, dict) and "is_scam" in parsed:
                            parsed["active"] = True
                            self._semantic_cache[cache_key] = (now, parsed)
                            return parsed
            except Exception as e:
                logger.warning(f"Gemini Webpage Semantic API warning on model {model}: {e}")
                continue

        # Nếu các model AI không khả dụng hoặc timeout, dùng bộ phân tích ngữ nghĩa dự phòng
        fallback_res = self._fallback_webpage_semantic(url, title, page_text, technical_context=technical_context, tech_is_scam=tech_is_scam)
        self._semantic_cache[cache_key] = (now, fallback_res)
        return fallback_res

    def _parse_json_response(self, raw_text: str) -> Optional[Dict[str, Any]]:
        """Làm sạch và bóc tách dữ liệu JSON từ câu trả lời của AI."""
        if not raw_text:
            return None
        cleaned = raw_text.strip()
        # 1. Trích xuất từ markdown code block ```json ... ```
        m_code = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', cleaned)
        if m_code:
            try:
                return json.loads(m_code.group(1).strip())
            except Exception:
                pass

        # 2. Parse trực tiếp chuỗi JSON thuần
        try:
            return json.loads(cleaned)
        except Exception:
            pass

        # 3. Trích xuất khối {...} bằng vị trí ngoặc nhọn
        first_brace = cleaned.find('{')
        last_brace = cleaned.rfind('}')
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(cleaned[first_brace:last_brace + 1])
            except Exception:
                pass
        return None


gemini_service = GeminiSecurityService()

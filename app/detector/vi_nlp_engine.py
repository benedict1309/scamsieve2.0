# File: app/detector/vi_nlp_engine.py
"""
Mô hình Ngôn ngữ Tiếng Việt Tối ưu (Optimized Vietnamese NLP & Intent Engine):
1. Phân tích Cấu trúc Ngữ nghĩa và Ý đồ (Linguistic Intent Analysis):
   - PROTECTIVE_WARNING: Lời khuyên cảnh báo an toàn bảo mật (Ngăn chặn False Positive).
   - COERCIVE_URGENCY: Ngữ cảnh đe dọa, áp lực thời gian, cưỡng ép (Khóa tài khoản, lệnh bắt).
   - SCAM_BAIT: Ngữ cảnh mồi chài phần thưởng, hoa hồng việc làm nạp tiền.
   - CREDENTIAL_HARVEST: Ngữ cảnh yêu cầu cung cấp thông tin nhạy cảm (OTP, mật khẩu, CCCD).
2. Xử lý Phạm vi Phủ định trong Tiếng Việt (Negation Scope Detection):
   - Phân biệt chính xác giữa:
     "Tuyệt đối KHÔNG cung cấp mã OTP" (Ý đồ bảo vệ, an toàn 100%)
     và "Yêu cầu cung cấp mã OTP" (Hành vi tấn công lừa đảo).
3. Tích hợp trực tiếp vào Pipeline điều phối điểm số với độ trễ siêu thấp (< 1ms).
"""
import re
import logging
from typing import Dict, Any, List, Optional
from app.detector.text_utils import normalize_text

logger = logging.getLogger(__name__)


class VietnameseNLPIntentEngine:
    def __init__(self):
        # 1. Các mẫu câu cảnh báo an toàn / Bảo vệ người dùng (Protective Warnings)
        self.protective_patterns = [
            re.compile(r'(?:tuyet\s+doi\s+)?(?:khong|de\s+phong)\s+(?:khong\s+)?(?:chia\s+se|cung\s+cap|nhap|gui|doc)\s+(?:ma\s+)?(?:otp|mat\s+khau|pin|ma\s+xac\s+thuc)', re.I),
            re.compile(r'(?:se\s+mat\s+tien|neu\s+cung\s+cap|canh\s+giac|can\s+than)\s+.*(?:otp|mat\s+khau)', re.I),
            re.compile(r'(?:khong\s+chia\s+se|khong\s+cung\s+cap|khong\s+doc)\s+(?:ma\s+)?(?:otp|xac\s+thuc)\s+cho\s+(?:bat\s+ky|ai)', re.I),
            re.compile(r'(?:ngan\s+hang|vi\s+dien\s+tu|nha\s+mang)\s+(?:khong\s+bao\s+gio|tuyet\s+doi\s+khong)\s+yeu\s+cau', re.I),
            re.compile(r'(?:neu\s+khong\s+phai\s+ban|neu\s+nghi\s+ngo\s+lua\s+dao)\s+vui\s+long\s+goi\s+(?:tong\s+dai|hotline)', re.I),
            re.compile(r'(?:canh\s+bao|canh\s+giac)\s+(?:thu\s+doan|chieu\s+tro)\s+(?:lua\s+dao|mao\s+danh)', re.I),
        ]

        # 2. Các mẫu đe dọa, hối thúc, áp lực thời gian (Coercive Urgency)
        self.coercive_patterns = [
            re.compile(r'(?:se\s+bi\s+khoa|tam\s+khoa|khoa\s+vinh\s+vien)\s+(?:sau|trong\s+vong)?\s*(?:\d+\s*(?:h|gio|ngay|phut))?', re.I),
            re.compile(r'(?:lenh\s+bat|lenh\s+trieu\s+tap|vien\s+kiem\s+sat|co\s+quan\s+dieu\s+tra)\s+.*(?:truy\s+to|bat\s+giam|rua\s+tien|buon\s+lau)', re.I),
            re.compile(r'(?:neu\s+khong\s+thuc\s+hien|neu\s+khong\s+chuyen\s+khoan)\s+se\s+(?:bi\s+khoa|phong\s+toa|truy\s+cuu)', re.I),
            re.compile(r'(?:chuyen\s+tien\s+ngay|chuyen\s+khoan\s+gap|nop\s+tien\s+ngay)\s+(?:de\s+khong\s+bi|vao\s+tai\s+khoan\s+tam\s+giu)', re.I),
            re.compile(r'(?:phat\s+hien\s+dang\s+nhap\s+bat\s+thuong|thiet\s+bi\s+la)\s+.*(?:dang\s+nhap\s+ngay|bam\s+link\s+de\s+huy)', re.I),
        ]

        # 3. Các mẫu mồi chài phần thưởng, việc làm, cờ bạc (Scam Bait)
        self.bait_patterns = [
            re.compile(r'(?:chuc\s+mung\s+ban\s+da\s+trung\s+thuong|trung\s+giai\s+dac\s+biet)\s+.*(?:dong\s+phi|chuyen\s+khoan\s+phi|nop\s+ho\s+so)', re.I),
            re.compile(r'(?:tuyen\s+dung\s+ctv|tuyen\s+nhan\s+vien\s+online)\s+.*(?:luong\s+ngay|hoa\s+hong|chot\s+don|kiem\s+tien\s+tai\s+nha)', re.I),
            re.compile(r'(?:tang\s+code|nap\s+dau\s+nhan|rut\s+tien\s+ve\s+atm)\s+.*(?:tai\s+xiu|no\s+hu|song\s+bac|baccarat|bet\d+)', re.I),
            re.compile(r'(?:giai\s+ngan\s+nhanh|vay\s+tien\s+khong\s+can\s+chung\s+minh)\s+.*(?:dong\s+phi\s+bao\s+hiem|chuyen\s+phi\s+truoc)', re.I),
        ]

        # 4. Yêu cầu chiếm đoạt thông tin nhạy cảm (Credential Harvest Action)
        self.harvest_patterns = [
            re.compile(r'(?:doc|gui|nhan\s+tin|cung\s+cap|nhap|cho\s+xin)\s+(?:giup\s+em\s+|cho\s+em\s+)?(?:ma\s+)?(?:otp|xac\s+thuc|mat\s+khau)', re.I),
            re.compile(r'(?:dang\s+nhap|truy\s+cap\s+lien\s+ket)\s+.*(?:de\s+mo\s+khoa|de\s+huy\s+giao\s+dich|de\s+nhan\s+qua)', re.I),
            re.compile(r'(?:tai\s+ung\s+dung|cai\s+dat\s+file)\s+.*(?:\.apk|ngoai\s+ch\s+play|theo\s+link)', re.I),
        ]

    def analyze_intent(self, text: str) -> Dict[str, Any]:
        """
        Phân tích toàn diện ngữ nghĩa ý đồ của thông điệp tiếng Việt:
        - protective_score: Mức độ bảo vệ/khuyến cáo an toàn (giảm rủi ro)
        - threat_score: Mức độ nguy hiểm do ép buộc/đe dọa/mồi chài (tăng rủi ro)
        - intent_category: Phân loại ý đồ chính
        """
        if not text or not text.strip():
            return {
                "intent_category": "NEUTRAL",
                "is_protective": False,
                "is_coercive": False,
                "is_bait": False,
                "is_credential_theft": False,
                "confidence_modifier": 0.0,
                "matched_clues": [],
            }

        norm_text = normalize_text(text)
        matched_clues = []

        # 1. Kiểm tra Ý đồ Bảo vệ (Protective Intent)
        is_protective = False
        for p in self.protective_patterns:
            m = p.search(text) or p.search(norm_text)
            if m:
                is_protective = True
                matched_clues.append(f"Khuyến cáo bảo mật an toàn: '{m.group(0)}'")
                break

        # 2. Kiểm tra Hành vi Chiếm đoạt thông tin nhạy cảm
        # 2. Kiểm tra Hành vi Chiếm đoạt thông tin nhạy cảm
        # Áp dụng Negation Scope Detection: Nếu có cụm bảo vệ, loại bỏ các cụm này trước khi tìm kiếm hành vi tấn công
        clean_for_harvest = text
        if is_protective:
            for pp in self.protective_patterns:
                clean_for_harvest = pp.sub('', clean_for_harvest)
        norm_clean_harvest = normalize_text(clean_for_harvest)

        is_credential_theft = False
        for p in self.harvest_patterns:
            m = p.search(clean_for_harvest) or p.search(norm_clean_harvest)
            if m:
                # Kiểm tra thêm phạm vi phủ định trực tiếp trong 40 ký tự phía trước (Negation Scope)
                start_idx = m.start()
                preceding_window = clean_for_harvest[max(0, start_idx - 40):start_idx].lower()
                neg_prefixes = ["khong", "không", "dung", "đừng", "tuyet doi khong", "tuyệt đối không", "canh giac", "cảnh giác"]
                if any(neg in preceding_window for neg in neg_prefixes):
                    continue
                is_credential_theft = True
                matched_clues.append(f"Dấu hiệu yêu cầu thông tin nhạy cảm: '{m.group(0)}'")
                break

        # 3. Kiểm tra Ý đồ Ép buộc / Đe dọa
        is_coercive = False
        for p in self.coercive_patterns:
            m = p.search(text) or p.search(norm_text)
            if m:
                is_coercive = True
                matched_clues.append(f"Dấu hiệu đe dọa / ép buộc tâm lý: '{m.group(0)}'")
                break

        # 4. Kiểm tra Ý đồ Mồi chài lừa đảo
        is_bait = False
        for p in self.bait_patterns:
            m = p.search(text) or p.search(norm_text)
            if m:
                is_bait = True
                matched_clues.append(f"Dấu hiệu mồi chài phần thưởng / việc làm ảo: '{m.group(0)}'")
                break

        # Xác định hạng mục ý đồ chính
        if is_protective and not is_credential_theft and not is_coercive:
            intent_category = "PROTECTIVE_WARNING"
            confidence_modifier = -80.0  # Giảm mạnh rủi ro
        elif is_credential_theft:
            intent_category = "CREDENTIAL_HARVEST"
            confidence_modifier = 65.0   # Tăng vọt rủi ro
        elif is_coercive:
            intent_category = "COERCIVE_URGENCY"
            confidence_modifier = 55.0   # Tăng rủi ro
        elif is_bait:
            intent_category = "SCAM_BAIT"
            confidence_modifier = 45.0   # Tăng rủi ro
        else:
            intent_category = "INFORMATIONAL_OR_NEUTRAL"
            confidence_modifier = 0.0

        return {
            "intent_category": intent_category,
            "is_protective": is_protective,
            "is_coercive": is_coercive,
            "is_bait": is_bait,
            "is_credential_theft": is_credential_theft,
            "confidence_modifier": confidence_modifier,
            "matched_clues": matched_clues,
        }


vi_nlp_engine = VietnameseNLPIntentEngine()

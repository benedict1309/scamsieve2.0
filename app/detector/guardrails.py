"""
Tầng 4: Bộ kiểm tra chéo, phản biện và tự sửa sai (Self-Correction & Guardrails).
Mục tiêu chính:
1. Triệt tiêu Dương tính giả (False Positives) đối với các tin nhắn cảnh báo an toàn từ ngân hàng.
2. Ngăn ngừa Âm tính giả (False Negatives) do lợi dụng danh nghĩa giao hàng/tiện ích để trộm OTP.
"""
import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ContextualGuardrail:
    def __init__(self):
        # Mẫu câu khuyến cáo bảo mật an toàn thường gặp trong tin nhắn chính thức của ngân hàng/ví điện tử
        self.bank_security_patterns = [
            re.compile(r'(?:tuyet doi|khong|de phong)\s+(?:khong\s+)?(?:chia se|cung cap|nhap|gui|doc)\s+(?:ma\s+)?(?:otp|mat khau)', re.I),
            re.compile(r'(?:se mat tien|neu cung cap|canh giac|can than)\s+.*(?:otp|mat khau)', re.I),
            re.compile(r'(?:khong chia se|khong cung cap|khong doc)\s+(?:ma\s+)?(?:otp|xac thuc)\s+cho\s+(?:bat ky|ai)', re.I),
            re.compile(r'neu\s+(?:quy khach|ban)\s+khong\s+thuc hien\s+vui long', re.I),
        ]

        # Từ khóa dịch vụ tiện ích, giao nhận thường ngày
        self.safe_service_keywords = [
            'hoc phi', 'truong dh', 'sinh vien', 'tien dien', 'tien nuoc', 
            'hoa don gach no', 'shipper', 'giao hang', 'nhan hang', 'don hang', 
            'giao lai', 'ma xac nhan', 'ezviz', 'account@'
        ]

    def has_bank_security_warning(self, text: str) -> bool:
        """Kiểm tra xem nội dung có chứa lời cảnh báo KHÔNG cung cấp OTP của ngân hàng hay không."""
        if not text:
            return False
        return any(p.search(text) for p in self.bank_security_patterns)

    def is_safe_service_bypass(self, text: str, has_threat_indicators: bool, has_urls: bool) -> bool:
        """
        Kiểm tra điều kiện để bypass ngữ cảnh an toàn.
        NGUYÊN TẮC BẢO VỆ CHỐNG ÂM TÍNH GIẢ:
        Chỉ cho phép bỏ qua kiểm tra KHI VÀ CHỈ KHI:
        - Có từ khóa tiện ích (giao hàng, tiền điện, học phí)
        - VÀ KHÔNG chứa URL
        - VÀ KHÔNG chứa hành vi đe dọa / đòi tiền / đòi mã OTP.
        """
        if not text or has_urls or has_threat_indicators:
            return False

        text_lower = text.lower()
        return any(kw in text_lower for kw in self.safe_service_keywords)

    def resolve_ensemble_score(
        self,
        rule_score: float,
        ml_score: float,
        has_warning: bool,
        has_threat: bool,
        has_critical: bool = False,
    ) -> float:
        """
        Hợp nhất điểm số giữa Rule-based và ML Model.
        Giải quyết xung đột và hiệu chỉnh độ tin cậy.
        """
        # Nếu là tin cảnh báo chính thống của ngân hàng (và không có hành vi đe dọa nghiêm trọng)
        if has_warning and not has_critical:
            return min(rule_score * 0.1, 15.0)

        # Nếu có dấu hiệu đe dọa nghiêm trọng thực sự (Critical Rule)
        if has_critical:
            return min(max(rule_score, ml_score, 75.0), 100.0)

        # Nếu ML xác nhận cực kỳ an toàn (xác suất lừa đảo <= 5%) và không có đe dọa hay rule nghi vấn cao
        if ml_score <= 5.0 and not has_threat:
            if rule_score < 40.0:
                return min(rule_score * 0.1, ml_score, 20.0)
            return rule_score

        # Nếu có dấu hiệu lừa đảo rõ ràng từ Rule
        if rule_score >= 60.0:
            return min(rule_score + (ml_score * 0.15), 100.0)

        # Nếu Rule ở mức nghi ngờ vừa hoặc ML cảnh báo, kết hợp 55% Rule + 45% ML
        if rule_score >= 20.0 or ml_score >= 40.0:
            combined = (rule_score * 0.55) + (ml_score * 0.45)
            return min(max(rule_score, combined), 100.0)

        return min(max(rule_score, ml_score * 0.5), 100.0)


guardrail = ContextualGuardrail()


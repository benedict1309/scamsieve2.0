# File: app/detector/url_ml_classifier.py
"""
Mô-đun Phân loại Phishing URL Chuẩn Công nghiệp (Industrial Real-Time URL Phishing Classifier)
Sử dụng mô hình LightGBM huấn luyện trên 20 đặc trưng Lexical & Cấu trúc thuần túy của chuỗi URL.
- 100% độc lập, không phụ thuộc vào việc crawl HTML (bỏ Link Density, External Links).
- Độ trễ cực thấp (< 0.1ms/URL).
- Tách biệt hoàn toàn khỏi mô hình NLP văn bản tiếng Việt.
"""
import math
import os
import re
import logging
import joblib
from collections import Counter
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

from app.detector.patterns.url_patterns import (
    SUSPICIOUS_TLDS,
    PHISHING_DOMAIN_KEYWORDS,
    COMBOSQUATTING_KEYWORDS
)

LEXICAL_FEATURE_NAMES = [
    "url_len",             # 1. Tổng độ dài URL
    "domain_len",          # 2. Độ dài tên miền
    "path_len",            # 3. Độ dài path
    "query_len",           # 4. Độ dài query
    "subdomain_count",     # 5. Số lượng cấp con subdomain
    "dot_count",           # 6. Số lượng dấu chấm
    "hyphen_count",        # 7. Số lượng dấu gạch nối (Domain squatting)
    "at_count",            # 8. Ký tự @ (Credential spoofing)
    "question_count",      # 9. Ký tự ?
    "percent_count",       # 10. Ký tự % (Mã hóa ngụy trang)
    "equal_count",         # 11. Ký tự =
    "slash_count",         # 12. Ký tự /
    "underscore_count",    # 13. Ký tự _
    "digit_ratio_url",     # 14. Tỷ lệ ký tự số trên toàn URL
    "digit_ratio_domain",  # 15. Tỷ lệ ký tự số trong tên miền
    "is_ip",               # 16. Địa chỉ IP làm host
    "entropy_url",         # 17. Độ hỗn loạn Shannon Entropy toàn URL
    "entropy_domain",      # 18. Độ hỗn loạn Shannon Entropy tên miền
    "suspicious_tld",      # 19. Thuộc TLD nguy cơ cao
    "has_phish_kw"         # 20. Chứa từ khóa tấn công / giả mạo
]


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_20_lexical_features(url_str: str) -> List[float]:
    """
    Trích xuất đúng 20 đặc trưng Lexical thuần túy trực tiếp từ chuỗi URL trong thời gian thực.
    """
    url = str(url_str or "").strip()
    parsed = urlparse(url if "://" in url else f"http://{url}")
    path = parsed.path
    query = parsed.query
    netloc = parsed.netloc.lower()

    # Bóc tách port nếu có
    if ':' in netloc:
        netloc = netloc.split(':')[0]

    domain_parts = netloc.split('.')
    subdomain_count = max(0, len(domain_parts) - 2) if len(domain_parts) >= 2 else 0

    digits_url = sum(c.isdigit() for c in url)
    digit_ratio_url = digits_url / max(len(url), 1)

    digits_domain = sum(c.isdigit() for c in netloc)
    digit_ratio_domain = digits_domain / max(len(netloc), 1)

    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', netloc))
    tld = domain_parts[-1] if domain_parts else ""
    suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    all_keywords = PHISHING_DOMAIN_KEYWORDS.union(COMBOSQUATTING_KEYWORDS)
    has_phish_kw = 1.0 if any(kw in url.lower() for kw in all_keywords) else 0.0

    return [
        float(len(url)),                                # 1. url_len
        float(len(netloc)),                             # 2. domain_len
        float(len(path)),                               # 3. path_len
        float(len(query)),                              # 4. query_len
        float(subdomain_count),                         # 5. subdomain_count
        float(url.count('.')),                          # 6. dot_count
        float(url.count('-')),                          # 7. hyphen_count
        float(url.count('@')),                          # 8. at_count
        float(url.count('?')),                          # 9. question_count
        float(url.count('%')),                          # 10. percent_count
        float(url.count('=')),                          # 11. equal_count
        float(url.count('/')),                          # 12. slash_count
        float(url.count('_')),                          # 13. underscore_count
        float(digit_ratio_url),                         # 14. digit_ratio_url
        float(digit_ratio_domain),                      # 15. digit_ratio_domain
        1.0 if is_ip else 0.0,                          # 16. is_ip
        float(calculate_entropy(url)),                  # 17. entropy_url
        float(calculate_entropy(netloc)),               # 18. entropy_domain
        float(suspicious_tld),                          # 19. suspicious_tld
        float(has_phish_kw)                             # 20. has_phish_kw
    ]


class URLPhishingClassifier:
    def __init__(self, model_path: Optional[str] = None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), 'url_lgbm_model.joblib')
        self.model = None
        self.feature_names = LEXICAL_FEATURE_NAMES
        try:
            if os.path.exists(model_path):
                bundle = joblib.load(model_path)
                if isinstance(bundle, dict):
                    self.model = bundle.get("model")
                    self.feature_names = bundle.get("feature_names", LEXICAL_FEATURE_NAMES)
                else:
                    self.model = bundle
                logger.info(f"Loaded URL LightGBM model from {model_path}")
        except Exception as e:
            logger.warning(f"Could not load URL LightGBM model: {e}")

    def predict(self, url: str) -> Dict[str, Any]:
        if not self.model or not url:
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "risk_score": 0.0,
                "model_available": False
            }
        
        features = extract_20_lexical_features(url)
        try:
            probs = self.model.predict_proba([features])[0]
            phishing_prob = float(probs[1])
            is_phishing = phishing_prob >= 0.5
            return {
                "is_phishing": is_phishing,
                "confidence": round(phishing_prob, 4),
                "risk_score": round(phishing_prob * 100.0, 1),
                "model_available": True
            }
        except Exception as e:
            logger.error(f"Error predicting URL phishing: {e}")
            return {
                "is_phishing": False,
                "confidence": 0.0,
                "risk_score": 0.0,
                "model_available": False
            }


url_classifier = URLPhishingClassifier()

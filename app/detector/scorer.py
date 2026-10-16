import logging
import os
import joblib
import re
from typing import Dict, Any, List

from app.detector.text_utils import preprocessor
from app.detector.patterns.url_patterns import url_extractor, SUSPICIOUS_TLDS
from app.detector.guardrails import guardrail
from app.models.enums import RiskLevel

logger = logging.getLogger(__name__)


class RiskScorer:
    def __init__(self):
        self.SCAM_THRESHOLD = 70.0
        self.SUSPICIOUS_TLDS = set(SUSPICIOUS_TLDS)

        # Danh sách Vùng an toàn dành cho Ngân hàng, Thương mại điện tử và Nền tảng Marketing uy tín
        self.TRUSTED_DOMAINS = [
            # Ngân hàng & Tài chính số Việt Nam
            'vib.com.vn', 'vietcombank.com.vn', 'techcombank.com.vn', 'mbbank.com.vn', 'acb.com.vn',
            'bidv.com.vn', 'agribank.com.vn', 'vpbank.com.vn', 'tpbank.com.vn', 'sacombank.com.vn', 'msb.com.vn',
            'vietinbank.vn', 'hdbank.com.vn', 'shb.com.vn', 'ocb.com.vn', 'seabank.com.vn', 'lpbank.com.vn',
            'momo.vn', 'zalopay.vn', 'vnpay.vn',
            'viettel.vn', 'vietteltelecom.vn', 'viettelmoney.vn', 'viettelpay.vn', 'vtp.vn',
            'tv360.vn', 'vtscloud.vn', 'viettelstore.vn',
            'mobifone.vn', 'mobifone.com.vn', 'vinaphone.vn', 'vinaphone.com.vn', 'vnpt.vn', 'vnptpay.vn', 'vnptmoney.vn', 'vietnamobile.com.vn',
            # Thương mại điện tử & Giao vận
            'shopee.vn', 'lazada.vn', 'tiki.vn', 'sendo.vn', 'grab.com', 'be.com.vn', 'ahamove.com',
            'thegioididong.com', 'dienmayxanh.com', 'fptshop.com.vn', 'cellphones.com.vn', 'hoanghamobile.com',
            'bachhoaxanh.com', 'ghn.vn', 'ghtk.vn', 'viettelpost.vn', 'vnpost.vn',
            # Cổng an toàn thông tin & Cơ quan
            'tinnhiemmang.vn', 'chongluadao.vn', 'ncsc.gov.vn', 'dichvucong.gov.vn', 'vneid.gov.vn',
            'chinhphu.vn', 'baochinhphu.vn', 'bocongan.gov.vn',
            # Báo chí & Truyền thông chính thống
            'vnexpress.net', 'dantri.com.vn', 'tuoitre.vn', 'thanhnien.vn', 'vietnamnet.vn', 'vtv.vn',
            'tienphong.vn', 'laodong.vn', 'soha.vn', 'kenh14.vn', 'znews.vn',
            # Học tập & Lập trình công nghệ
            'stackoverflow.com', 'github.com', 'gitlab.com', 'leetcode.com', 'codeforces.com',
            'hackerrank.com', 'w3schools.com', 'kaggle.com', 'geeksforgeeks.org', 'npmjs.com',
            'pypi.org', 'python.org', 'developer.mozilla.org', 'coursera.org', 'udemy.com', 'wikipedia.org',
            # Mạng xã hội & Nền tảng toàn cầu
            'google.com', 'google.com.vn', 'youtube.com', 'microsoft.com', 'apple.com',
            'facebook.com', 'fb.com', 'messenger.com', 'instagram.com', 'threads.net',
            'claude.ai', 'claude.com', 'anthropic.com', 'openai.com', 'chatgpt.com',
            'tiktok.com', 'twitter.com', 'x.com',
            # Nền tảng tiếp thị & Chuyển hướng an toàn
            'onelink.me', 'go.link', 'goo.gl', 'garena.vn', 'ezviz.com',
            # Môi trường nội bộ
            'localhost', '127.0.0.1'
        ]

        self.ml_model = None
        model_path = os.path.join(os.path.dirname(__file__), 'ml_model.joblib')
        try:
            if os.path.exists(model_path):
                self.ml_model = joblib.load(model_path)
            else:
                logger.warning("ML model not found. Please run scripts/train_model.py first.")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")

    def analyze_message(self, raw_text: str) -> Dict[str, Any]:
        result = {
            "is_scam": False,
            "risk_score": 0.0,
            "reason": [],
            "risk_level": "LOW",
        }
        if not raw_text or not raw_text.strip():
            return result

        try:
            urls = url_extractor.extract_urls(raw_text)
            url_features_list = [url_extractor.extract_features(url) for url in urls]

            # Chuẩn hóa văn bản không dấu để khớp chính xác cả tiếng Việt có dấu, không dấu và teencode
            from app.detector.text_utils import normalize_text
            normalized_msg = normalize_text(raw_text)

            # Kiểm tra xem có dấu hiệu đe dọa / trộm OTP / ép chuyển tiền / cờ bạc cá cược không
            has_threat = bool(
                re.search(
                    r'(?:doc|gui|nhap|lay|xin|dien\s+ngay)\s+(?:[a-z\s]{0,10}\s+)?(?:ma\s+)?(?:otp|nay|xac\s+thuc|xac\s+minh)|'
                    r'cung\s+cap\s+(?:ma\s+)?(?:otp|xac\s+thuc|xac\s+minh|bao\s+mat)\s+(?:cho\s+nguoi\s+khac|qua\s+dien\s+thoai)|'
                    r'(?:chuoi\s+(?:ky\s+tu|ma|so)|ma\s+(?:xac\s+thuc|xac\s+minh|bao\s+mat|6\s+so)|day\s+so)\b.*?(?:gui|nhan|may|cung cap|doc)|'
                    r'chuyen\s+(?:gap|tien|khoan)|phong toa|lenh bat|\.apk|tai\s+xiu|song\s+(?:bac|bai|tai\s+xiu)|ca\s+(?:cuoc|do)|no\s+hu|casino|baccarat|'
                    r'(?:tai\s+khoan\s+con\s+thuong|luot\s+quay\s+mien\s+phi|nhan\s+li\s+xi|hoan\s+tien\s+\d+%)|'
                    r'(?:lich\s+cat\s+dien|ngung\s+cap\s+dien).*?(?:no\s+tien|can\s+bo)|'
                    r'(?:nhan\s+(?:lam|chay)?\s*(?:\[name\]|[a-z0-9_-]+)?\s*(?:bang|gplx|cmnd|cccd|giay\s+to|lxe|dai\s+hoc))|'
                    r'(?:tu\s+dong\s+thu\s+chi\s+trong\s+tai\s+khoan)|'
                    r'(?:neu\s+(?:khong|khg)\s+(?:phai|dang\s+ky)|bam\s+(?:vao\s+)?link\s+de\s+huy|huy\s+cuoc)',
                    normalized_msg,
                )
            )
            # Kiểm tra dấu hiệu lừa đảo tuyển dụng / việc nhẹ lương cao / làm nhiệm vụ
            has_job_scam = bool(
                re.search(
                    r'(?:tuyen\s+(?:dung|nhan\s+vien|ctv|gap|hoi\s+vien)|cong\s+tac\s+vien|truong\s+phong\s+nhan\s+su|cty\s+(?:dang\s+)?tuyen)\b.*?'
                    r'(?:ban\s+thoi\s+gian|part\s*time|online|tai\s+nha|luong\s+ngay|tra\s+hang\s+ngay|hoa\s+hong|thu\s+nhap|viec\s+nhe|don\s+gian)'
                    r'|'
                    r'(?:viec\s+nhe\s+luong\s+cao|lam\s+nhiem\s+vu|chot\s+don|tang\s+tuong\s+tac|danh\s+gia\s+san\s+pham)\b'
                    r'|'
                    r'(?:cong\s+viec\s+online|kiem\s+them\s+thu\s+nhap|thu\s+nhap.*?\/.*?(?:ngay|thang)|lam\s+viec\s+tai\s+nha)'
                    r'|'
                    r'(?:tang\s+lop\s+hoc|hoc\s+qua\s+zoom|hoc\s+mien\s+phi|tang\s+them\s+qua\s+gia\s+tri|vao\s+nhom\s+zalo)',
                    normalized_msg
                )
            )
            has_scam_indicator = has_threat or has_job_scam
            has_security_warning = guardrail.has_bank_security_warning(raw_text)

            # BỘ LỌC NGỮ CẢNH AN TOÀN (CÓ KIỂM SOÁT GUARDRAIL - CHỐNG BẪY ÂM TÍNH GIẢ)
            if guardrail.is_safe_service_bypass(raw_text, has_threat_indicators=has_scam_indicator, has_urls=bool(urls)):
                result["reason"].append("Safe educational/billing/shipping context bypass (Verified no threat)")
                result["risk_level"] = "LOW"
                return result

            # 1. TẦNG BẢO VỆ TUYỆT ĐỐI (Contextual Whitelist & Blacklist O(1))
            all_urls_trusted = bool(url_features_list) and all(
                any(f.get("netloc", "") == domain or f.get("netloc", "").endswith('.' + domain) for domain in self.TRUSTED_DOMAINS)
                and not f.get("is_suspicious_tld")
                and not f.get("is_brand_impersonation")
                for f in url_features_list
            )

            for features in url_features_list:
                netloc = features.get("netloc", "")

                # Miễn trừ điểm phạt URL nếu tên miền thuộc cơ quan, ngân hàng hoặc tổ chức chính thống
                # (Không bỏ qua toàn bộ để tránh trường hợp kẻ gian chèn link tin cậy kèm văn bản lừa đảo)
                is_gov_edu = (netloc.endswith('.gov.vn') or netloc.endswith('.edu.vn')) and not has_threat
                from app.services.blacklist_service import threat_intel
                is_safe, is_malicious = threat_intel.check_domain_risk(netloc)
                
                if is_malicious:
                    result["is_scam"] = True
                    result["risk_score"] = 100.0
                    result["reason"].append(f"Blacklisted malicious domain: {netloc}")
                    result["risk_level"] = "HIGH"
                    return result

                if is_gov_edu or (all_urls_trusted and any(netloc == domain or netloc.endswith('.' + domain) for domain in self.TRUSTED_DOMAINS)) or is_safe:
                    features["is_trusted_domain"] = True
                    result["reason"].append(f"Tên miền chính thống được xác thực: {netloc}")

            # Nếu nội dung chỉ là một URL chính thống độc lập (không kèm văn bản đe dọa lừa đảo)
            words = raw_text.split()
            is_standalone_url = len(words) <= 2 and bool(urls)
            has_credential_alert = bool(re.search(r'(?:mat khau|password|telegram code|ma dang nhap|bi lo|bi lo thong tin|dang nhap vao|ro ri|ma xac minh)', raw_text.lower()))
            if all_urls_trusted and not has_scam_indicator and not has_credential_alert:
                if is_standalone_url:
                    result["risk_score"] = 0.0
                    result["is_scam"] = False
                    result["risk_level"] = "LOW"
                    return result

            # 2. CHẤM ĐIỂM TỔNG HỢP (ML + Heuristics + Obfuscation + Phishing/Email)
            score = 0.0

            obfuscation_score = preprocessor.extract_obfuscation_score(raw_text)
            has_evasion_noise = bool(re.search(r'(?:<[-=]{1,2}){2,}|(?:[-=]{1,2}>){2,}|(?:\.[\<\>]){2,}', raw_text))
            if obfuscation_score >= 0.35 or has_evasion_noise:
                score += 75.0
                result["reason"].append(f"Cảnh báo cấp độ cao: Phát hiện chuỗi ngụy trang/xáo trộn ký tự nặng ({obfuscation_score * 100:.1f}%)")
            elif obfuscation_score > 0.15:
                score += 25.0
                result["reason"].append(f"Phát hiện ký tự ẩn/ngụy trang tinh vi ({obfuscation_score * 100:.1f}%)")

            # Đánh giá URL và giả mạo tên miền (Typosquatting)
            url_risk_score = self._evaluate_url_heuristics(url_features_list)
            score += url_risk_score
            for features in url_features_list:
                if features.get("is_brand_impersonation"):
                    detail = features.get("impersonation_info", {}).get("detail", "")
                    result["reason"].append(f"Mạo danh thương hiệu/Typosquatting: {detail}")
            if url_risk_score > 0 and not any(f.get("is_brand_impersonation") for f in url_features_list):
                result["reason"].append(f"Dấu hiệu URL đáng ngờ (+{url_risk_score:.0f} điểm)")

            # Đánh giá Email rác nặc danh hoặc mạo danh cơ quan
            from app.detector.patterns.url_patterns import extract_emails, DISPOSABLE_EMAIL_DOMAINS, FREE_EMAIL_DOMAINS
            emails = extract_emails(raw_text)
            for email in emails:
                parts = email.lower().split("@")
                if len(parts) == 2:
                    user_part, domain = parts
                    if domain in DISPOSABLE_EMAIL_DOMAINS:
                        score += 40.0
                        result["reason"].append(f"Địa chỉ email rác nặc danh: {email}")
                    elif domain in FREE_EMAIL_DOMAINS:
                        org_indicators = [
                            "cong an", "toaan", "toa an", "vien kiem sat", "bo cong an", "vneid",
                            "chinh phu", "cuc an ninh", "cuc thue", "tong cuc thue", "bao hiem xa hoi", "bhxh",
                            "ngan hang", "vietcombank", "techcombank", "bidv", "agribank", "mbbank",
                            "vpbank", "acb", "sacombank", "tpbank", "vib", "cskh", "tong dai",
                            "shopee", "lazada", "tiki", "momo", "viettel", "vinaphone", "mobifone"
                        ]
                        user_clean = user_part.replace(".", "").replace("_", "").replace("-", "")
                        normalized_raw = preprocessor.normalize(raw_text).lower()
                        if any(org.replace(" ", "") in user_clean for org in org_indicators) or any(org in normalized_raw for org in org_indicators):
                            score += 45.0
                            result["reason"].append(f"Mạo danh tổ chức qua email miễn phí: {email}")

            ml_score = 0.0
            if self.ml_model:
                words = raw_text.split()
                if len(words) <= 10 and not urls and not emails and obfuscation_score < 0.20 and not has_scam_indicator:
                    logger.info("Bypassed AI scoring for short URL-free conversational message.")
                else:
                    from app.detector.text_utils import prepare_model_input
                    model_input = prepare_model_input(raw_text)
                    ml_prob = self.ml_model.predict_proba([model_input])[0][1]
                    ml_score = ml_prob * 100.0

                    if ml_score >= 70.0:
                        score = max(score, ml_score * 0.85)
                        result["reason"].append(f"Mô hình AI phát hiện ngữ nghĩa lừa đảo với độ tin cậy cao ({ml_score:.1f}%)")
                    elif ml_score > 50.0:
                        score += ml_score * 0.4
                        result["reason"].append(f"Phân tích ngữ nghĩa AI cảnh báo nghi vấn ({ml_score:.1f}% xác suất)")

                    # Phân tích sâu ngữ cảnh với PhoBERT (triệt tiêu thủ thuật lách từ)
                    try:
                        from app.detector.phobert_classifier import phobert_detector
                        if phobert_detector.is_loaded:
                            sem_eval = phobert_detector.compute_semantic_threat_score(raw_text)
                            if sem_eval.get("is_phobert_available"):
                                sem_threat = sem_eval.get("semantic_threat_score", 0.0)
                                if sem_threat >= 70.0 and not has_security_warning:
                                    score = max(score, sem_threat * 0.85)
                                    result["reason"].append(f"PhoBERT Context: Nhận diện ý đồ tấn công ngữ cảnh ({sem_threat:.1f}%)")
                                elif sem_threat < 40.0 and has_security_warning:
                                    ml_score = min(ml_score, 10.0)
                    except Exception:
                        pass

            # Hiệu chỉnh qua Guardrail (xóa điểm phạt nếu là tin cảnh báo ngân hàng)
            final_score = guardrail.resolve_ensemble_score(
                rule_score=score,
                ml_score=ml_score,
                has_warning=has_security_warning,
                has_threat=has_threat,
            )

            result["risk_score"] = min(round(final_score, 1), 100.0)

            # Phân loại theo RiskLevel chuẩn
            if result["risk_score"] >= self.SCAM_THRESHOLD:
                result["is_scam"] = True
                result["risk_level"] = "HIGH"
            elif result["risk_score"] >= (self.SCAM_THRESHOLD * 0.55):
                result["risk_level"] = "MEDIUM"
            else:
                result["risk_level"] = "LOW"

            return result

        except Exception as e:
            logger.error(f"Error during message scoring: {str(e)}", exc_info=True)
            return result

    def _evaluate_url_heuristics(self, url_features_list: List[Dict]) -> float:
        score = 0.0
        for features in url_features_list:
            if features.get("is_trusted_domain"):
                continue
            if features.get("is_ip_domain"):
                score += 80.0
            if features.get("subdomain_count", 0) >= 2:
                score += 10.0
            if features.get("is_shortened"):
                score += 10.0
            if features.get("is_brand_impersonation"):
                imp_type = features.get("impersonation_info", {}).get("type", "")
                if imp_type == "HOMOGLYPH_ATTACK":
                    score += 80.0
                elif imp_type == "TUNNEL_HOSTING_ABUSE":
                    score += 75.0
                elif imp_type == "SUBDOMAIN_DECEPTION":
                    score += 75.0
                elif imp_type == "COMBOSQUATTING":
                    score += 70.0
                else:
                    score += 65.0
            if features.get("has_credential_spoofing"):
                score += 75.0
            if features.get("is_open_redirect_abuse"):
                score += 70.0
            if features.get("is_obfuscated_ip"):
                score += 75.0
            if features.get("has_phishing_keyword"):
                score += 35.0
            if features.get("is_dga"):
                score += 50.0

            netloc = features.get("netloc", "")
            parts = netloc.split('.')
            if parts:
                tld = parts[-1].lower()
                if tld in self.SUSPICIOUS_TLDS:
                    score += 25.0
        return score

    def evaluate_unified_risk(
        self,
        content: str,
        raw_matches: List[Any],
        phone_info: Any = None,
    ) -> Dict[str, Any]:
        """
        Kiến trúc Đồng bộ và Chuẩn hóa Điểm số (Unified & Standardized Scoring Architecture):
        Hợp nhất toàn diện giữa Heuristic Rules, Danh sách đen/trắng, Guardrails và Mô hình ML Soft-Voting.
        Đảm bảo Đánh giá tĩnh (System rules) và Đánh giá dữ liệu (ML model) hoàn toàn nhất quán.
        """
        matches = list(raw_matches)
        content_clean = content.strip() if content else ""

        # 1. Nhận diện các quy tắc đe dọa nghiêm trọng (Critical Threats)
        hard_critical_rule_ids = {
            "otp_share_request", "app_install_apk", "reverse_otp_scam",
            "threat_arrest_freeze", "malware_apk_link", "impersonate_court_police",
            "dga_random_domain", "brand_impersonation_url", "credential_spoofing_url",
            "open_redirect_abuse", "obfuscated_ip_address",
            "illegal_gambling", "job_recruitment_scam", "disposable_email_domain",
            "display_name_email_spoofing", "free_email_impersonation",
            "disposable_phishing_domain_age", "blacklisted_phone",
            "blacklisted_domain", "telecom_prefix_intelligence",
            "url_lexical_ml_threat", "suspicious_url", "raw_ip_domain"
        }
        has_hard_critical = any(getattr(m, 'rule_id', '') in hard_critical_rule_ids for m in matches)
        has_critical_rule = has_hard_critical or any(getattr(m, 'rule_id', '') == "vision_scam_evidence" for m in matches)
        rule_score = total_score(matches)

        # 2. Phân tích ngữ cảnh đe dọa và kiểm tra Guardrail
        urls = url_extractor.extract_urls(content_clean)
        url_features_list = [url_extractor.extract_features(u) for u in urls]

        # 2b. Phân tích Ý đồ Ngôn ngữ Tiếng Việt Tối ưu (Vietnamese NLP Intent Engine)
        from app.detector.vi_nlp_engine import vi_nlp_engine
        nlp_intent = vi_nlp_engine.analyze_intent(content_clean)

        has_security_warning = guardrail.has_bank_security_warning(content_clean) or nlp_intent.get("is_protective", False)

        threat_text = content_clean.lower()
        if has_security_warning:
            threat_text = re.sub(
                r'(?:tuyet\s+doi\s+)?(?:khong|de\s+phong)\s+(?:khong\s+)?(?:chia\s+se|cung\s+cap|nhap|gui|doc)\s+(?:ma\s+)?(?:otp|mat\s+khau|xac\s+thuc)[^.]*',
                '',
                threat_text
            )
            threat_text = re.sub(
                r'(?:se\s+mat\s+tien|neu\s+cung\s+cap|canh\s+giac|can\s+than)[^.]*(?:otp|mat\s+khau)',
                '',
                threat_text
            )

        has_threat = bool(
            re.search(
                r'(?:doc|gui|cung cap|nhap|lay|xin)\s+(?:ma\s+)?otp|chuyen\s+(?:gap|tien|khoan)|phong toa|lenh bat|\.apk|tai\s+xiu|song\s+(?:bac|bai|tai\s+xiu)|ca\s+(?:cuoc|do)|no\s+hu|casino|baccarat',
                threat_text,
            )
        ) or nlp_intent.get("is_credential_theft", False) or nlp_intent.get("is_coercive", False)

        has_job_scam = bool(
            re.search(
                r'(?:tuyen\s+(?:dung|nhan\s+vien|ctv|gap)|cong\s+tac\s+vien|truong\s+phong\s+nhan\s+su|cty\s+(?:dang\s+)?tuyen)\b.*?'
                r'(?:ban\s+thoi\s+gian|part\s*time|online|tai\s+nha|luong\s+ngay|tra\s+hang\s+ngay|hoa\s+hong|thu\s+nhap|viec\s+nhe|don\s+gian)'
                r'|'
                r'(?:viec\s+nhe\s+luong\s+cao|lam\s+nhiem\s+vu|chot\s+don|tang\s+tuong\s+tac|danh\s+gia\s+san\s+pham)\b',
                threat_text
            )
        ) or nlp_intent.get("is_bait", False)

        has_scam_indicator = has_threat or has_job_scam or has_hard_critical

        # Kiểm tra Vùng an toàn (Bypass): Gov/Edu, Trusted Brands, Tiện ích giáo dục/hóa đơn
        is_safe_service = guardrail.is_safe_service_bypass(content_clean, has_threat_indicators=has_scam_indicator, has_urls=bool(urls))
        is_trusted_domain = False
        if not has_scam_indicator and urls:
            is_trusted_domain = all(
                any(
                    f.get("netloc", "").endswith("." + d) or f.get("netloc", "") == d
                    or f.get("netloc", "").endswith(".gov.vn") or f.get("netloc", "") == "gov.vn"
                    or f.get("netloc", "").endswith(".edu.vn") or f.get("netloc", "") == "edu.vn"
                    for d in self.TRUSTED_DOMAINS
                )
                for f in url_features_list
            )
        is_bank_warning = (has_security_warning and not has_threat and not has_hard_critical)

        # 3. Phân tích mô hình học máy (The AI Brain)
        safe_prob = 100.0
        scam_prob = 0.0
        obfuscation = 0.0
        words = content_clean.split()
        is_standalone_url = len(words) <= 2 and bool(urls)
        is_short_conversational = len(words) <= 12 and not urls

        if self.ml_model and content_clean:
            try:
                obfuscation = preprocessor.extract_obfuscation_score(content_clean)
                if is_short_conversational:
                    safe_prob = 98.0
                    scam_prob = 2.0
                elif is_standalone_url:
                    # Đánh giá URL độc lập qua pipeline chuyên biệt
                    url_analysis = self.analyze_message(content_clean)
                    url_risk_val = url_analysis.get("risk_score", 0.0)
                    if url_analysis.get("risk_level") == "LOW" or url_risk_val == 0.0:
                        safe_prob = 100.0
                        scam_prob = 0.0
                    elif url_risk_val >= 70.0:
                        scam_prob = float(url_risk_val)
                        safe_prob = max(0.0, 100.0 - scam_prob)
                    elif rule_score == 0 and not has_scam_indicator:
                        safe_prob = 100.0
                        scam_prob = 0.0
                    else:
                        scam_prob = float(min(max(rule_score, url_risk_val), 100.0))
                        safe_prob = max(0.0, 100.0 - scam_prob)
                else:
                    from app.detector.text_utils import prepare_model_input
                    model_input = prepare_model_input(content_clean)
                    probs = self.ml_model.predict_proba([model_input])[0]
                    safe_prob = float(probs[0]) * 100.0
                    scam_prob = float(probs[1]) * 100.0
            except Exception as e:
                logger.error(f"ML evaluation error in unified engine: {e}")
                safe_prob = max(0.0, 100.0 - rule_score)
                scam_prob = float(rule_score)
        else:
            safe_prob = max(0.0, 100.0 - rule_score)
            scam_prob = float(rule_score)

        # 4. Thuật toán Hiệu chỉnh Điểm số Thống nhất (Harmonized Calibration)
        reasons = []

        # TÌNH HUỐNG 1: Xác nhận An toàn qua Whitelist / Guardrail / Cảnh báo bảo mật
        if is_safe_service or is_bank_warning or (is_trusted_domain and rule_score == 0 and not has_scam_indicator and scam_prob < 30.0):
            matches = [m for m in matches if getattr(m, 'rule_id', '') in hard_critical_rule_ids]
            unified_score = 0
            risk_level = RiskLevel.LOW
            status_label = "Nội dung an toàn"
            summary = "Được xác thực an toàn qua hệ thống nhận diện tổ chức chính thống và không phát hiện hành vi đe dọa."
            display_scam_prob = min(scam_prob, 5.0)
            reasons.append("Xác nhận an toàn qua Vùng đối soát tổ chức chính thống")

        # TÌNH HUỐNG 2: Phát hiện Đe dọa Nghiêm trọng (Critical Threats)
        elif has_hard_critical or has_threat:
            unified_score = int(min(max(rule_score, scam_prob, 75.0), 100.0))
            risk_level = RiskLevel.HIGH
            status_label = "Nguy cơ rủi ro cao"
            summary = "Nội dung chứa dấu hiệu lừa đảo nguy hiểm (đe dọa, trộm OTP, mã độc APK, cờ bạc hoặc thông tin danh sách đen)."
            display_scam_prob = max(scam_prob, 85.0)
            reasons.append("Phát hiện hành vi đe dọa nghiêm trọng")

        # TÌNH HUỐNG 3: ML Khẳng định Cực kỳ An toàn (P_safe >= 95%) và KHÔNG có Hard Critical Threats
        elif safe_prob >= 95.0 and not has_hard_critical:
            matches = []
            unified_score = int(min(rule_score * 0.1, scam_prob, 15.0))
            risk_level = RiskLevel.LOW
            status_label = "Nội dung an toàn"
            summary = "Nội dung an toàn, không ghi nhận dấu hiệu độc hại hoặc kịch bản lừa đảo."
            display_scam_prob = round(scam_prob, 1)
            reasons.append(f"Mô hình dữ liệu khẳng định an toàn cao ({safe_prob:.1f}%)")

        # TÌNH HUỐNG 4: ML Khẳng định Nguy cơ Cao (P_scam >= 70%) mà Rule chưa bắt được
        elif scam_prob >= 70.0 and not is_short_conversational:
            from app.detector.base import RuleMatch
            if not any(getattr(m, 'rule_id', '') == 'semantic_scam_pattern' for m in matches):
                matches.append(
                    RuleMatch(
                        rule_id="semantic_scam_pattern",
                        category="Phát hiện liên kết lừa đảo qua AI",
                        snippet=content_clean[:75] + ("..." if len(content_clean) > 75 else ""),
                        score=int(min(scam_prob, 85)),
                        explanation=f"Mô hình AI phát hiện liên kết / kịch bản có dấu hiệu lừa đảo với độ tin cậy cao ({scam_prob:.1f}% xác suất).",
                    )
                )
            matches.sort(key=lambda m: getattr(m, 'score', 0), reverse=True)
            unified_score = int(min(max(rule_score, scam_prob), 100.0))
            risk_level = RiskLevel.HIGH if unified_score >= 70 else RiskLevel.MEDIUM
            status_label = "Nguy cơ rủi ro cao"
            summary = "Mô hình AI phát hiện liên kết / kịch bản mang nguy cơ lừa đảo cao."
            display_scam_prob = round(scam_prob, 1)
            reasons.append(f"Mô hình AI cảnh báo kịch bản lừa đảo ({scam_prob:.1f}%)")

        # TÌNH HUỐNG 5: Hợp nhất Trọng số Tổng quát (Weighted Ensemble Blend)
        else:
            calibrated = (rule_score * 0.55) + (scam_prob * 0.45)
            if obfuscation > 0.15:
                calibrated = min(calibrated + 15.0, 100.0)
            unified_score = int(min(round(calibrated), 100))
            risk_level = classify_risk(unified_score)

            if risk_level == RiskLevel.HIGH:
                status_label = "Nguy cơ rủi ro cao"
                summary = "Nội dung mang dấu hiệu lừa đảo hoặc dẫn dụ chuyển tiền, đánh cắp thông tin."
            elif risk_level == RiskLevel.MEDIUM:
                status_label = "Cần thận trọng"
                summary = "Nội dung có biểu hiện nghi vấn, cần xác minh danh tính người gửi."
            else:
                status_label = "Nội dung thông thường"
                summary = "Chưa ghi nhận dấu hiệu lừa đảo rõ ràng từ các kênh kiểm tra."
            display_scam_prob = round(scam_prob, 1)

        ai_result = {
            "active": True,
            "scam_prob": round(display_scam_prob, 1),
            "safe_prob": round(safe_prob, 1),
            "is_scam": risk_level == RiskLevel.HIGH,
            "is_suspicious": risk_level == RiskLevel.MEDIUM,
            "is_bypassed": is_short_conversational or is_safe_service or is_trusted_domain or is_standalone_url,
            "confidence": round(scam_prob if risk_level == RiskLevel.HIGH else safe_prob, 1),
            "obfuscation_ratio": round(obfuscation * 100, 1),
            "has_obfuscation": obfuscation > 0.15,
            "status_label": status_label,
            "summary": summary,
        }

        return {
            "score": unified_score,
            "risk_level": risk_level,
            "matches": matches,
            "ai_result": ai_result,
            "reasons": reasons,
        }


scorer = RiskScorer()


def total_score(matches: list) -> int:
    """Tính tổng điểm rủi ro từ danh sách rule matches (tối đa 100 điểm)."""
    if not matches:
        return 0
    return min(sum(m.score for m in matches), 100)


def classify_risk(score: float | int) -> RiskLevel:
    """Phân loại mức độ rủi ro: LOW (<40), MEDIUM (40-69), HIGH (>=70)."""
    if score >= 70:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def score_and_classify(matches: list) -> tuple[int, RiskLevel]:
    """Tính tổng điểm và phân loại rủi ro cho danh sách RuleMatch."""
    score = total_score(matches)
    risk_level = classify_risk(score)
    return score, risk_level
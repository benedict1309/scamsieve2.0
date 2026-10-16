"""
Dịch vụ Quản lý Báo cáo và Đóng góp Dữ liệu Cộng đồng (Community Threat Intelligence).
Xử lý:
1. Tiếp nhận phản ánh, báo cáo lừa đảo hoặc xác nhận an toàn từ người dùng.
2. Thống kê số lượt phản ánh của cộng đồng theo Số điện thoại / URL / Nội dung.
3. Tự động nâng mức độ rủi ro (Threat Escalation) khi một đầu mối nhận nhiều lượt phản ánh.
4. Tự động bổ sung vào Blacklist hệ thống khi đạt ngưỡng tin cậy.
"""
import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.report import Report
from app.models.blacklist import Blacklist
from app.models.enums import ContentType, ReportStatus, RiskLevel
from app.detector.base import RuleMatch
from app.detector.phone_utils import extract_phone_candidates, analyze_sender_risk
from app.detector.heuristics import evaluate_heuristics
from app.detector.rules import detect_all
from app.detector.scorer import score_and_classify

logger = logging.getLogger(__name__)


def _normalize_content_for_lookup(content: str, content_type: Optional[ContentType] = None) -> str:
    """
    Chuẩn hóa nội dung để đối soát và đếm lượt báo cáo chính xác:
    - Số điện thoại: đưa về dạng chuỗi số thuần không dấu cách (vd 0981234567).
    - URL: đưa về chữ thường, bỏ dấu gạch chéo cuối.
    - Văn bản: bỏ khoảng trắng thừa ở hai đầu.
    """
    c = content.strip()
    if not c:
        return ""

    # Nếu là số điện thoại hoặc trông giống số điện thoại
    candidates = extract_phone_candidates(c)
    if candidates and len(candidates) == 1 and len(c.replace(" ", "").replace(".", "").replace("-", "")) <= 13:
        return candidates[0]

    # Nếu là URL
    if c.lower().startswith("http://") or c.lower().startswith("https://"):
        return c.lower().rstrip("/")

    return c


def verify_report_threat_instantly(
    content: str,
    content_type: ContentType,
    scam_type: Optional[str] = None,
    reporter_note: Optional[str] = None,
    db: Optional[Session] = None,
) -> Dict[str, Any]:
    """
    Quy trình Thẩm định Tự động Tức thì bằng AI & Heuristic Đa tầng (Instant Threat Verification).
    Thẩm định ngay khi người dùng bấm Gửi báo cáo, bóc tách dấu hiệu lừa đảo và
    kích hoạt bảo vệ toàn mạng lưới nếu đạt ngưỡng tin cậy cao mà không cần chờ đợi.
    """
    clean_content = (content or "").strip()
    clean_note = (reporter_note or "").strip()
    full_context = f"{clean_content} {scam_type or ''} {clean_note}".strip()
    normalized = _normalize_content_for_lookup(clean_content, content_type) or clean_content

    # 1. Kiểm tra đối soát với Danh sách đen Blacklist
    if db:
        existing_bl = db.query(Blacklist).filter(Blacklist.value == normalized).first()
        if existing_bl:
            return {
                "verdict": "VERIFIED_SCAM",
                "is_verified": True,
                "confidence": 0.99,
                "confidence_pct": 99,
                "reason": "Đối tượng đã nằm trong Danh sách đen quốc gia / cơ sở dữ liệu gian lận",
                "scam_category": scam_type or "Gian lận đã xác thực",
                "action": "blacklist_hit",
            }

    # 2. Thẩm định chuyên sâu theo loại đối tượng
    # A. Đường dẫn Website (URL)
    is_url_target = (
        content_type == ContentType.URL or
        clean_content.lower().startswith(("http://", "https://")) or
        any(tld in clean_content.lower() for tld in [".com", ".vn", ".net", ".org", ".xyz", ".top", ".cc", ".site"])
    )
    if is_url_target:
        try:
            heuristics_res = evaluate_heuristics(url=clean_content, db=db)
            penalty = heuristics_res.get("penalty_score", 0)
            verdict = heuristics_res.get("verdict", "")
            danger_flags = heuristics_res.get("danger_flags", [])

            if verdict == "DANGEROUS" or danger_flags or penalty >= 50:
                flag_text = danger_flags[0] if danger_flags else "Vi phạm nhiều tiêu chí an toàn web (Heuristics)"
                conf_pct = min(98, max(82, int(penalty)))
                return {
                    "verdict": "VERIFIED_SCAM",
                    "is_verified": True,
                    "confidence": conf_pct / 100,
                    "confidence_pct": conf_pct,
                    "reason": f"AI phát hiện dấu hiệu lừa đảo: {flag_text}",
                    "scam_category": "Website giả mạo / Phishing",
                    "action": "auto_blacklist",
                }
            elif verdict == "SUSPICIOUS" or penalty >= 25:
                return {
                    "verdict": "SUSPICIOUS",
                    "is_verified": False,
                    "confidence": 0.60,
                    "confidence_pct": 60,
                    "reason": "Tên miền có đuôi bất thường hoặc đường dẫn khả nghi",
                    "scam_category": scam_type or "Website nghi vấn",
                    "action": "monitor",
                }
        except Exception as e:
            logger.warning(f"Error evaluating URL heuristics in instant verification: {e}")

    # B. Số điện thoại (Phone)
    is_phone_target = (content_type == ContentType.PHONE or clean_content.replace("+", "").replace(".", "").replace(" ", "").isdigit())
    if is_phone_target:
        try:
            phone_analysis = analyze_sender_risk(clean_content)
            phone_score = phone_analysis.get("risk_score", 0)
            anomalies = phone_analysis.get("anomalies", [])

            if phone_score >= 60 or (anomalies and any("quốc tế" in a.lower() or "voip" in a.lower() for a in anomalies)):
                return {
                    "verdict": "VERIFIED_SCAM",
                    "is_verified": True,
                    "confidence": 0.90,
                    "confidence_pct": 90,
                    "reason": f"Đầu số viễn thông bất thường: {anomalies[0] if anomalies else 'VoIP giả mạo'}",
                    "scam_category": scam_type or "Cuộc gọi / Tin nhắn lừa đảo",
                    "action": "auto_blacklist",
                }
        except Exception as e:
            logger.warning(f"Error evaluating phone risk in instant verification: {e}")

    # C. Tài khoản ngân hàng (Bank account)
    if content_type == ContentType.BANK_ACCOUNT:
        suspicious_bank_kws = ["nạp tiền", "hoa hồng", "nhiệm vụ", "đóng phí", "hoàn đơn", "sàn", "telegram", "chuyển khoản gấp", "bảo hiểm vốn"]
        has_fraud_kw = any(kw in full_context.lower() for kw in suspicious_bank_kws)
        if has_fraud_kw:
            return {
                "verdict": "VERIFIED_SCAM",
                "is_verified": True,
                "confidence": 0.85,
                "confidence_pct": 85,
                "reason": "Tài khoản nhận tiền có dấu hiệu thủ đoạn bẫy nạp tiền làm nhiệm vụ",
                "scam_category": scam_type or "Tài khoản gian lận",
                "action": "auto_blacklist",
            }
        else:
            return {
                "verdict": "SUSPICIOUS",
                "is_verified": False,
                "confidence": 0.55,
                "confidence_pct": 55,
                "reason": "Tài khoản ngân hàng bị cộng đồng phản ánh nghi vấn",
                "scam_category": scam_type or "Tài khoản nghi vấn",
                "action": "monitor",
            }

    # D. Kịch bản văn bản / Tin nhắn (Rules & Keywords)
    try:
        matches = detect_all(full_context)
        if matches:
            score, risk_level = score_and_classify(matches)
            if risk_level == RiskLevel.HIGH or score >= 60:
                categories = [m.category for m in matches if getattr(m, 'category', None)]
                top_cat = categories[0] if categories else "Kịch bản lừa đảo nguy hiểm"
                conf_pct = min(96, max(80, int(score)))
                return {
                    "verdict": "VERIFIED_SCAM",
                    "is_verified": True,
                    "confidence": conf_pct / 100,
                    "confidence_pct": conf_pct,
                    "reason": f"AI nhận diện thủ đoạn: {top_cat}",
                    "scam_category": top_cat,
                    "action": "auto_blacklist",
                }
            elif risk_level == RiskLevel.MEDIUM or score >= 35:
                return {
                    "verdict": "SUSPICIOUS",
                    "is_verified": False,
                    "confidence": score / 100,
                    "confidence_pct": int(score),
                    "reason": "Nội dung có biểu hiện bất thường hoặc gây áp lực tâm lý",
                    "scam_category": scam_type or "Kịch bản nghi vấn",
                    "action": "monitor",
                }
    except Exception as e:
        logger.warning(f"Error detecting rules in instant verification: {e}")

    # E. Nếu có từ khóa lừa đảo rõ ràng trong ghi chú / scam_type
    critical_keywords = [
        "công an", "viện kiểm sát", "lệnh bắt", "smart otp", "trộm otp",
        "nhiệm vụ shopee", "nạp hoa hồng", "khóa sim", "đòi nợ cước"
    ]
    if any(ck in full_context.lower() for ck in critical_keywords):
        return {
            "verdict": "VERIFIED_SCAM",
            "is_verified": True,
            "confidence": 0.82,
            "confidence_pct": 82,
            "reason": "Khớp mẫu kịch bản lừa đảo phổ biến đã được cảnh báo",
            "scam_category": scam_type or "Thủ đoạn lừa đảo",
            "action": "auto_blacklist",
        }

    # F. Mặc định: Tiếp nhận và ghi nhận nghi vấn
    return {
        "verdict": "SUSPICIOUS",
        "is_verified": False,
        "confidence": 0.50,
        "confidence_pct": 50,
        "reason": "Tiếp nhận phản ánh từ cộng đồng, đang đối soát với dữ liệu an toàn",
        "scam_category": scam_type or "Dấu hiệu nghi vấn",
        "action": "monitor",
    }


def submit_community_report(
    db: Session,
    content: str,
    content_type: ContentType,
    scam_type: Optional[str] = None,
    reporter_note: Optional[str] = None,
    reporter_ip: Optional[str] = None,
    is_scam: bool = True,
) -> Report:
    """
    Tiếp nhận, thẩm định tự động tức thì bằng AI và lưu trữ báo cáo từ cộng đồng.
    Tự động khóa và đưa ngay vào Blacklist nếu AI xác thực dấu hiệu lừa đảo rõ ràng.
    """
    normalized_content = _normalize_content_for_lookup(content, content_type)
    full_note = (scam_type + ": " if scam_type else "") + (reporter_note or "")

    # Chạy quy trình Thẩm định Tự động Tức thì bằng AI & Heuristic
    verification = verify_report_threat_instantly(
        content=content,
        content_type=content_type,
        scam_type=scam_type,
        reporter_note=reporter_note,
        db=db,
    )

    verdict = verification.get("verdict", "SUSPICIOUS")
    confidence_pct = verification.get("confidence_pct", 50)
    reason = verification.get("reason", "")
    is_verified_scam = verification.get("is_verified", False)

    # Nếu AI thẩm định xác thực lừa đảo -> phê duyệt ngay (APPROVED), ngược lại giữ PENDING
    if is_verified_scam and is_scam:
        status = ReportStatus.APPROVED
    else:
        status = ReportStatus.PENDING if is_scam else ReportStatus.REJECTED

    admin_note = f"AI_VERIFIED: {verdict} | confidence={confidence_pct}% | reason={reason}"

    new_report = Report(
        content_type=content_type,
        content=normalized_content or content.strip(),
        reporter_note=full_note.strip() if full_note else None,
        reporter_ip=reporter_ip,
        status=status,
        admin_note=admin_note,
        created_at=datetime.utcnow(),
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    # Đính kèm kết quả thẩm định vào đối tượng trả về
    setattr(new_report, "verification_result", verification)

    # CƠ CHẾ BẢO VỆ TỨC THÌ (INSTANT THREAT PROTECTION):
    # 1. Nếu AI Thẩm định Tức thì xác thực lừa đảo -> Khóa ngay lập tức vào Blacklist
    if is_verified_scam and normalized_content:
        existing_bl = db.query(Blacklist).filter(Blacklist.value == normalized_content).first()
        if not existing_bl:
            auto_bl = Blacklist(
                content_type=content_type,
                value=normalized_content,
                note=f"Tự động khóa bởi AI Thẩm định tức thì ({confidence_pct}%): {reason}",
                source="ai_instant_verified",
                source_report_id=new_report.id,
                created_at=datetime.utcnow(),
            )
            db.add(auto_bl)
            db.commit()
            logger.info(f"Instant AI Verification: Auto-blacklisted {normalized_content} with {confidence_pct}% confidence.")

    # 2. Cơ chế đồng thuận số đông (Crowdsource Consensus):
    # Nếu nội dung có từ 2 lượt báo cáo trở lên từ cộng đồng -> Khóa bổ sung
    if is_scam and normalized_content:
        total_reports = (
            db.query(Report)
            .filter(
                Report.content == normalized_content,
                Report.status != ReportStatus.REJECTED,
            )
            .count()
        )

        if total_reports >= 2:
            existing_bl = db.query(Blacklist).filter(Blacklist.value == normalized_content).first()
            if not existing_bl:
                auto_bl = Blacklist(
                    content_type=content_type,
                    value=normalized_content,
                    note=f"Tự động khóa bởi phản ánh cộng đồng ({total_reports} lượt báo cáo)",
                    source="community_crowdsource",
                    source_report_id=new_report.id,
                    created_at=datetime.utcnow(),
                )
                db.add(auto_bl)
                db.commit()
                logger.info(f"Auto-added {normalized_content} to Blacklist based on {total_reports} community reports.")

    return new_report


def get_community_stats(content: str, db: Session) -> Dict[str, Any]:
    """
    Tra cứu số liệu phản ánh của cộng đồng đối với một nội dung/số điện thoại/URL.
    Bao gồm tỷ lệ tín nhiệm cộng đồng (Xác nhận an toàn vs Báo cáo lừa đảo).
    """
    if not content or not content.strip():
        return {
            "total_reports": 0,
            "is_reported": False,
            "scam_count": 0,
            "safe_count": 0,
            "total_votes": 0,
            "safe_pct": 0,
            "scam_pct": 0,
            "scam_types": [],
            "recent_reports": [],
        }

    normalized = _normalize_content_for_lookup(content)
    target = normalized or content.strip()

    # Tìm các báo cáo lừa đảo (status != REJECTED)
    reports = (
        db.query(Report)
        .filter(
            (Report.content == target) | (Report.content.like(f"%{target}%")),
            Report.status != ReportStatus.REJECTED,
        )
        .order_by(Report.created_at.desc())
        .limit(5)
        .all()
    )

    scam_count = (
        db.query(Report)
        .filter(
            (Report.content == target) | (Report.content.like(f"%{target}%")),
            Report.status != ReportStatus.REJECTED,
        )
        .count()
    )

    safe_count = (
        db.query(Report)
        .filter(
            (Report.content == target) | (Report.content.like(f"%{target}%")),
            Report.status == ReportStatus.REJECTED,
        )
        .count()
    )

    total_votes = scam_count + safe_count
    if total_votes > 0:
        safe_pct = round((safe_count / total_votes) * 100)
        scam_pct = 100 - safe_pct
    else:
        safe_pct = 0
        scam_pct = 0

    scam_types: List[str] = []
    for r in reports:
        if r.reporter_note:
            parts = r.reporter_note.split(":", 1)
            t = parts[0].strip()
            if t and t not in scam_types and t != "Xác nhận an toàn":
                scam_types.append(t)

    return {
        "total_reports": scam_count,
        "is_reported": total_votes > 0,
        "scam_count": scam_count,
        "safe_count": safe_count,
        "total_votes": total_votes,
        "safe_pct": safe_pct,
        "scam_pct": scam_pct,
        "scam_types": scam_types[:3],
        "latest_reported_at": reports[0].created_at if reports else None,
    }


def check_community_reputation_matches(content: str, db: Session) -> List[RuleMatch]:
    """
    Tích hợp trực tiếp vào Pipeline Detector:
    Nếu nội dung / số điện thoại / URL đã từng bị người dùng khác báo cáo,
    sinh ra RuleMatch với điểm số tương ứng để cảnh báo ngay cho người tra cứu.
    """
    if not content or not content.strip():
        return []

    stats = get_community_stats(content, db)
    total = stats.get("total_reports", 0)

    if total == 0:
        return []

    # Phân cấp mức điểm cảnh báo theo số lượt báo cáo từ cộng đồng
    if total == 1:
        score = 35
        category = "Cảnh báo từ cộng đồng (1 lượt báo cáo)"
        explanation = "Số điện thoại hoặc nội dung này đã từng có 1 người dùng phản ánh dấu hiệu bất thường."
    elif total <= 3:
        score = 65
        category = f"Cảnh báo từ cộng đồng ({total} lượt báo cáo)"
        types_text = f" ({', '.join(stats['scam_types'])})" if stats.get("scam_types") else ""
        explanation = f"Đã có {total} lượt người dùng báo cáo nội dung này có dấu hiệu lừa đảo{types_text}."
    else:
        score = 90
        category = f"Nguy cơ cao: Cộng đồng phản ánh liên tục ({total} lượt báo cáo)"
        types_text = f" ({', '.join(stats['scam_types'])})" if stats.get("scam_types") else ""
        explanation = f"Nội dung này nhận được rất nhiều phản ánh lừa đảo từ người dân{types_text}. Tuyệt đối không giao dịch."

    return [
        RuleMatch(
            rule_id="community_reputation_alert",
            category=category,
            snippet=content[:80] + ("..." if len(content) > 80 else ""),
            score=score,
            explanation=explanation,
        )
    ]


def get_recent_public_alerts(db: Session, limit: int = 8) -> List[Dict[str, Any]]:
    """
    Lấy danh sách các cảnh báo mới nhất vừa được cộng đồng gửi về
    để hiển thị lên bảng tin công khai.
    Tự động che bớt các số điện thoại nhạy cảm (vd 024.7300.xxx) để giữ quyền riêng tư.
    """
    reports = (
        db.query(Report)
        .filter(Report.status != ReportStatus.REJECTED)
        .order_by(Report.created_at.desc())
        .limit(limit)
        .all()
    )

    type_labels = {
        "phone": "Số điện thoại",
        "url": "Đường link",
        "bank_account": "Tài khoản ngân hàng",
        "text": "Nội dung / Tin nhắn",
    }

    alerts: List[Dict[str, Any]] = []
    for r in reports:
        raw_val = r.content
        masked_val = raw_val

        # Che số điện thoại nếu là số di động hoặc cố định
        digits = re.sub(r"\D", "", raw_val)
        if len(digits) >= 9 and digits.isdigit() and len(digits) <= 12 and not any(c in raw_val for c in ["http", "www", "com", "vn"]):
            masked_val = digits[:6] + "xxx" + digits[-1]
        elif len(raw_val) > 120:
            masked_val = raw_val[:118] + "..."

        scam_label = "Dấu hiệu đáng ngờ"
        detail_note = r.reporter_note or "Cộng đồng vừa báo cáo"
        if r.reporter_note and ":" in r.reporter_note:
            parts = r.reporter_note.split(":", 1)
            candidate_label = parts[0].strip()
            if len(candidate_label) <= 60:
                scam_label = candidate_label
                detail_note = parts[1].strip()

        ct_val = r.content_type.value if hasattr(r.content_type, "value") else str(r.content_type).lower()
        type_label = type_labels.get(ct_val.lower(), "Phản ánh")

        # Trích xuất kết quả thẩm định tự động tức thì từ admin_note
        is_verified = False
        confidence_pct = None
        verification_label = "Đang đối soát"
        if r.admin_note and "AI_VERIFIED:" in r.admin_note:
            if "VERIFIED_SCAM" in r.admin_note:
                is_verified = True
                verification_label = "Đã xác thực lừa đảo"
            elif "SUSPICIOUS" in r.admin_note:
                verification_label = "Ghi nhận nghi vấn"

            conf_match = re.search(r"confidence=(\d+)%", r.admin_note)
            if conf_match:
                confidence_pct = int(conf_match.group(1))
        elif r.status == ReportStatus.APPROVED:
            is_verified = True
            verification_label = "Đã xác thực"

        alerts.append({
            "id": r.id,
            "type": ct_val,
            "content_type_label": type_label,
            "display_target": masked_val,
            "scam_label": scam_label,
            "scam_type": scam_label,
            "detail_note": detail_note,
            "reporter_note": detail_note,
            "is_verified": is_verified,
            "verification_label": verification_label,
            "confidence_pct": confidence_pct,
            "time_ago": r.created_at.strftime("%d/%m/%Y %H:%M"),
            "created_at": r.created_at.strftime("%d/%m/%Y %H:%M"),
        })

    return alerts


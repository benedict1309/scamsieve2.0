# File: scripts/sync_threat_intel.py
"""
Script Dòng lệnh Tự động Đồng bộ Tình báo Mối đe dọa (URLhaus, OpenPhish, P-Sieve Seeds).
Cách chạy:
    python -m scripts.sync_threat_intel --limit 500
"""
import sys
import os
import argparse
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SyncThreatIntel")

from app.database import SessionLocal
from app.services.threat_feed_service import threat_feed_service


def main():
    parser = argparse.ArgumentParser(description="Đồng bộ nguồn cấp Tình báo Mối đe dọa An ninh Mạng (Threat Feeds)")
    parser.add_argument("--limit", type=int, default=300, help="Số lượng bản ghi tối đa lấy từ mỗi nguồn cấp (mặc định: 300)")
    parser.add_argument("--offline-only", action="store_true", help="Chỉ nạp các hạt giống ngoại tuyến core seeds")
    args = parser.parse_args()

    print("=" * 70)
    print("P-SIEVE CYBERSHIELD - TIẾN TRÌNH ĐỒNG BỘ NGUỒN TÌNH BÁO MỐI ĐE DỌA")
    print("=" * 70)

    db = SessionLocal()
    try:
        res = threat_feed_service.sync_all_feeds(
            db=db,
            limit_per_feed=args.limit,
            include_offline_seeds=True
        )

        print(f"\n[+] Kết quả đồng bộ:")
        print(f"    - Thời điểm hoàn tất: {res['timestamp']}")
        print(f"    - Nguồn cấp đã đồng bộ: {', '.join(res['sources'])}")
        print(f"    - Tên miền mới lưu vào SQLite Blacklist: +{res['new_db_domains_inserted']}")
        print(f"    - Tổng tên miền độc hại trong RAM Cache: {res['total_domains_in_memory']}")
        print(f"\n[✓] {res['message']}\n")

    except Exception as e:
        logger.error(f"Lỗi trong quá trình đồng bộ Threat Intel: {e}", exc_info=True)
    finally:
        db.close()


if __name__ == "__main__":
    main()


"""
Import danh sach so dien thoai lua dao tu file CSV vao bang Blacklist.

Ho tro doc file CSV ma moi dong bi Excel boc trong 1 dau ngoac kep duy nhat
(vd: "19003439,domestic_premium,+1900,call_scam,...,hatinh.gov.vn") - day la
kieu loi thuong gap khi noi dung duoc dan vao 1 o duy nhat roi xuat CSV.
Neu file la CSV chuan (co nhieu cot that su), script van doc dung binh thuong.

Cach chay (tu thu muc goc du an, sau khi da kich hoat venv):

    python -m scripts.import_blacklist_csv --file duong/dan/den/file.csv

Tuy chon:
    --admin-id <id>   Gan created_by_admin_id cho tai khoan admin thuc hien import
                       (bo qua neu chua co tai khoan admin nao - de None).

File CSV can co dung 6 cot theo thu tu:
    phone_number, prefix_type, country_code, category, note, source
"""
import argparse
import csv
import sys

from app.database import SessionLocal, Base, engine
from app.models.enums import ContentType
from app.models.blacklist import Blacklist
# Dam bao Base.metadata biet het cac bang truoc khi create_all
from app.models import user, report, scan  # noqa: F401

EXPECTED_HEADER = ["phone_number", "prefix_type", "country_code", "category", "note", "source"]


def read_csv_rows(path: str) -> list[list[str]]:
    """
    Doc file CSV, tu dong xu ly ca 2 truong hop:
    1. CSV chuan, nhieu cot.
    2. Moi dong bi boc trong 1 dau "..." duy nhat (loi thuong gap tu Excel).
    Luon doc bang utf-8-sig de tu dong bo qua BOM neu co.
    """
    rows: list[list[str]] = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            if line.startswith('"') and line.endswith('"'):
                line = line[1:-1]
            row = next(csv.reader([line]))
            rows.append(row)
    return rows


def import_csv(path: str, admin_id: int | None) -> None:
    rows = read_csv_rows(path)
    if not rows:
        print("File rong, khong co gi de import.")
        return

    header, data_rows = rows[0], rows[1:]
    if [h.strip() for h in header] != EXPECTED_HEADER:
        print(f"CANH BAO: header khong khop chuan {EXPECTED_HEADER}")
        print(f"Header doc duoc: {header}")
        print("Dung lai de kiem tra file truoc khi import.")
        sys.exit(1)

    # Dam bao bang da ton tai
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    inserted, skipped_duplicate, skipped_bad_row = 0, 0, 0

    try:
        for i, row in enumerate(data_rows, start=2):  # dong 2 vi dong 1 la header
            if len(row) != len(EXPECTED_HEADER):
                print(f"  [Bo qua] Dong {i}: so cot khong khop ({len(row)} != {len(EXPECTED_HEADER)}): {row}")
                skipped_bad_row += 1
                continue

            phone_number, prefix_type, country_code, category, note, source = [c.strip() for c in row]

            # Kiem tra trung: da co so nay trong Blacklist voi content_type=PHONE chua
            existing = (
                db.query(Blacklist)
                .filter(Blacklist.content_type == ContentType.PHONE, Blacklist.value == phone_number)
                .first()
            )
            if existing:
                skipped_duplicate += 1
                continue

            full_note = f"{note} (loai: {prefix_type}, ma: {country_code}, category: {category})"

            entry = Blacklist(
                content_type=ContentType.PHONE,
                value=phone_number,
                note=full_note,
                source=source,
                source_report_id=None,
                created_by_admin_id=admin_id,
            )
            db.add(entry)
            inserted += 1

        db.commit()
    finally:
        db.close()

    print("--- Ket qua import ---")
    print(f"Tong dong du lieu doc duoc: {len(data_rows)}")
    print(f"Da them moi:                {inserted}")
    print(f"Bo qua (da ton tai):        {skipped_duplicate}")
    print(f"Bo qua (loi dinh dang):     {skipped_bad_row}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import blacklist so dien thoai tu CSV")
    parser.add_argument("--file", required=True, help="Duong dan file CSV")
    parser.add_argument("--admin-id", type=int, default=None, help="ID tai khoan admin thuc hien import")
    args = parser.parse_args()

    import_csv(args.file, args.admin_id)

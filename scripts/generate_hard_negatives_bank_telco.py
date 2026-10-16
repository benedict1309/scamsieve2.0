# File: scripts/generate_hard_negatives_bank_telco.py
"""
Bộ sinh tập dữ liệu đối kháng (Hard Negative Mining Synthesizer):
Bổ sung 700+ mẫu tin nhắn chính thống đa dạng từ các ngân hàng, nhà mạng,
nền tảng công nghệ lớn và đời sống thực tế chứa từ khóa nhạy cảm:
1. Giao dịch, biến động số dư, thanh toán hóa đơn
2. Mã xác thực OTP thông thường (Zalo, Google, Apple, Vietcombank, Shopee, MoMo)
3. Cảnh báo bảo mật ("KHÔNG cung cấp OTP cho bất kỳ ai", "Cảnh báo thủ đoạn mạo danh")
4. Khuyến mãi nạp thẻ, đăng ký gói cước data 4G viễn thông
5. Giao hàng, shipper, logistics (GHTK, GHN, Shopee Xpress)
6. Tin nhắn công việc / giao tiếp thường nhật (tiền ăn trưa, công nợ thông thường)

Giúp triệt tiêu lỗi nhận diện nhầm (False Positive / Zero-overfitting).
"""
import csv
import os
import sys
import random
from datetime import datetime

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

data_path = 'data/labeled_messages.csv'

BANKS = [
    ("VCB", "Vietcombank", "001100", "VCB Digibank"),
    ("TCB", "Techcombank", "1903", "Techcombank Mobile"),
    ("MB", "MBBank", "8820", "MB Bank App"),
    ("ACB", "ACB", "2184", "ACB ONE"),
    ("BIDV", "BIDV", "1201", "BIDV SmartBanking"),
    ("VPB", "VPBank", "1508", "VPBank NEO"),
    ("TPB", "TPBank", "0342", "TPBank Mobile"),
    ("VIB", "VIB", "0482", "MyVIB 2.0"),
    ("STB", "Sacombank", "0501", "Sacombank Pay")
]

TELCOS = ["Viettel", "MobiFone", "Vinaphone"]

TECH_PLATFORMS = [
    ("Google", "Ma xac minh Google cua ban la"),
    ("Apple", "Your Apple ID verification code is"),
    ("Microsoft", "Ma xac thuc tai khoan Microsoft:"),
    ("Zalo", "Ma xac thuc Zalo cua ban la"),
    ("Shopee", "Ma OTP ShopeePay cua ban la"),
    ("MoMo", "Ma OTP vi MoMo cua ban la"),
    ("TikTok", "Ma dang nhap TikTok cua ban la"),
    ("Facebook", "Ma xac nhan bao mat Facebook la")
]

TRANSACTION_TYPES = [
    "Chuyen tien nhanh 247 den TK",
    "Thanh toan hoa don dien EVN",
    "Thanh toan tien nuoc sach",
    "Thanh toan phi bao hiem",
    "Nap tien dien thoai qua",
    "Thanh toan don hang Shopee",
    "Thanh toan QR Pay tai sieu thi",
    "Rut tien mat tai ATM",
    "Mo so tiet kiem online ky han"
]

PSA_WARNINGS = [
    "khuyen cao: Tuyet doi KHONG chia se ma OTP, mat khau, ten dang nhap voi bat ky ai duoi moi hinh thuc de phong tranh bi ke gian chiem doat tien.",
    "canh bao: Ngan hang KHONG BAO GIO yeu cau quy khach cung cap ma OTP hoac truy cap vao duong link la de xac thuc hay nhan tien.",
    "luu y: Ma xac thuc OTP la khoa bao mat toi thuong. Neu cung cap OTP cho nguoi la, quy khach se bi mat tien trong tai khoan.",
    "thong bao: Canh giac voi cac cuoc goi mao danh co quan chuc nang (Cong an, Toa an) yeu cau chuyen tien. Ngan hang tuyet doi khong yeu cau chuyen tien vao tai khoan tam giu.",
    "khuyen nghi: Khong bam vao cac lien ket nhan qua, tang tien tren mang xa hoi. Moi giao dich chi thuc hien tren ung dung chinh thuc."
]

LOGISTICS = ["GHTK", "GHN", "Shopee Xpress", "Viettel Post", "J&T Express"]

NAMES = ["Nguyen Van A", "Tran Thi B", "Le Van C", "Pham Thi D", "Hoang Van E", "Vu Thi M"]


def generate_samples(count=700):
    samples = []

    # 1. Mẫu OTP ngân hàng an toàn (không phải lừa đảo)
    for _ in range(count // 7):
        bank_code, bank_name, prefix, app = random.choice(BANKS)
        trans = random.choice(TRANSACTION_TYPES)
        otp = random.randint(100000, 999999)
        amount = f"{random.randint(50, 15000) * 1000:,.0f} VND"
        text = f"{bank_code}: Quy khach dang thuc hien {trans}. So tien: {amount}. Ma OTP xac thuc giao dich la {otp}, hieu luc trong 3 phut. Luu y: KHONG chia se OTP cho bat ky ai."
        samples.append(text)

    # 2. Mẫu OTP từ các nền tảng công nghệ lớn (Google, Apple, Zalo, Microsoft, Shopee)
    for _ in range(count // 7):
        plat, msg_prefix = random.choice(TECH_PLATFORMS)
        otp = random.randint(100000, 999999)
        if plat == "Apple":
            text = f"{msg_prefix} {otp}. Do not share it with anyone."
        else:
            text = f"{plat}: {msg_prefix} {otp}. Ma co hieu luc trong 5 phut. Vui long KHONG chia se ma nay voi bat ky ai duoi moi hinh thuc."
        samples.append(text)

    # 3. Mẫu Cảnh báo bảo mật ngân hàng (Security PSAs - Hard Negatives)
    for _ in range(count // 7):
        _, bank_name, _, _ = random.choice(BANKS)
        psa = random.choice(PSA_WARNINGS)
        hotline = f"1900{random.randint(1000, 9999)}"
        text = f"{bank_name} {psa} Neu nghi ngo lua dao, quy khach vui long lien he ngay tong dai {hotline} de khoa tai khoan khan cap."
        samples.append(text)

    # 4. Mẫu Biến động số dư tài khoản ngân hàng
    for _ in range(count // 7):
        bank_code, _, prefix, app = random.choice(BANKS)
        acc_num = f"{prefix}{random.randint(100000, 999999)}"
        is_plus = random.choice([True, False])
        diff = f"{'+' if is_plus else '-'}{random.randint(20, 5000) * 1000:,.0f} VND"
        bal = f"{random.randint(1000, 50000) * 1000:,.0f} VND"
        time_str = f"{random.randint(7, 21):02d}:{random.randint(0, 59):02d}"
        notes = ["Thanh toan tien dien", "Luong thang nay", "Chuyen tien an trua", "Tra tien hang", "Chuyen khoan 247"]
        text = f"{bank_code}: TK {acc_num} thay doi {diff} luc {time_str}. So du kha dung: {bal}. Ref: {random.choice(notes)} qua {app}."
        samples.append(text)

    # 5. Mẫu Nhà mạng khuyến mãi & gói cước viễn thông
    packages = ["ST120K", "ST30K", "SD135", "KC90", "BIG90", "V90C", "TK50"]
    for _ in range(count // 7):
        telco = random.choice(TELCOS)
        pkg = random.choice(packages)
        data = f"{random.choice([2, 3, 5, 30, 60, 90])}GB"
        fee = f"{random.choice([30, 50, 70, 90, 120, 135])}.000d"
        text = f"[TB] {telco} thong bao: Quy khach da dang ky thanh cong goi cuoc {pkg} ({fee}/thang, co {data} data toc do cao). De kiem tra dung luong soan KTTK gui 191 hoac goi tong dai 198 (mien phi)."
        samples.append(text)

    # 6. Mẫu Giao hàng Logistics & Thương mại điện tử
    for _ in range(count // 7):
        shipper_svc = random.choice(LOGISTICS)
        order_id = f"ORD{random.randint(100000, 999999)}"
        cod = f"{random.randint(50, 800) * 1000:,.0f} VND"
        phone = f"09{random.randint(10000000, 99999999)}"
        text = f"{shipper_svc}: Don hang {order_id} dang duoc giao den ban boi nhan vien giao hang ({phone}). Tien thu ho COD: {cod}. Vui long kiem tra hang khi nhan."
        samples.append(text)

    # 7. Mẫu Tin nhắn giao tiếp đời sống & công việc thường ngày
    chat_templates = [
        "To vua chuyen tra cau {amount} tien an com trua nhe, cau check tai khoan giup to voi.",
        "Em gui anh bao gia moi nhat qua email roi, anh xem co gi phan hoi lai giup em nhe.",
        "Toi nay may gio ca nhom minh gap nhau o quan ca phe the? Nho mang theo may tinh.",
        "Chieu nay tam 3h em qua van phong gui lai anh hop dong da ky nhe.",
        "Minh da thanh toan tien tien dien thang nay roi nhe, tong cong het {amount}.",
        "Can phong minh da dat thanh cong cho chuyen di Da Lat cuoi tuan nay, hen gap ca nha."
    ]
    for _ in range(count // 7):
        tmpl = random.choice(chat_templates)
        amount = f"{random.randint(30, 800) * 1000:,.0f}d"
        text = tmpl.format(amount=amount)
        samples.append(text)

    return samples


def append_to_dataset():
    existing_texts = set()
    rows = []
    fieldnames = ['message_id', 'date', 'text', 'label']

    if os.path.exists(data_path):
        with open(data_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cleaned_row = {k.replace('\ufeff', ''): v for k, v in row.items()}
                existing_texts.add(cleaned_row.get('text', '').strip().lower())
                rows.append(cleaned_row)

    init_count = len(rows)
    print(f"Số mẫu hiện tại trong tập dữ liệu: {init_count}")

    new_samples = generate_samples(700)
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    added_count = 0

    for i, s in enumerate(new_samples, start=1):
        clean_text = s.strip()
        if clean_text.lower() not in existing_texts:
            existing_texts.add(clean_text.lower())
            rows.append({
                'message_id': f'HN_REALISTIC_{i:04d}',
                'date': now_str,
                'text': clean_text,
                'label': '0'
            })
            added_count += 1

    with open(data_path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Đã bổ sung thành công: {added_count} mẫu Hard Negative đối kháng vào {data_path}!")
    print(f"Tổng số mẫu mới sau khi cập nhật: {len(rows)}")


if __name__ == '__main__':
    append_to_dataset()

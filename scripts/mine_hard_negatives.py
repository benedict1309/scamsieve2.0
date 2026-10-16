# File: scripts/mine_hard_negatives.py
"""
Script Khai phá và Bổ sung Mẫu biên (Hard Negative Mining & Adversarial Augmentation):
1. Bổ sung các mẫu âm khó (Hard Negatives - Label 0):
   - Tin khuyến mãi, nạp thẻ, gói cước viễn thông thật (Viettel, Vinaphone, MobiFone)
   - Tin tiếp thị, tặng voucher, tri ân từ sàn TMĐT và ứng dụng thanh toán (Shopee, Lazada, Tiki, Grab, MoMo)
   - Tin biến động số dư, giao dịch ngân hàng và cảnh báo bảo mật ngân hàng chính thống
   - Tin thông báo dịch vụ công, thuế, BHXH (VssID), tiền điện EVN, tiền nước
   - Tin giao hàng thật từ Shipper (GHTK, GHN, Shopee Xpress, VNPost, J&T)
   - Tin gửi mã OTP thông thường (không đòi hỏi đọc hay gửi lại)
2. Bổ sung các mẫu dương đối kháng (Hard Positives / Adversarial Scams - Label 1):
   - Lừa đảo ngụy trang ký tự, teencode, lừa đảo tuyển dụng CTV tinh vi
   - Lừa đảo tâm lý đảo ngược (Reverse OTP), bẫy phí lưu kho, trạm BTS giả mạo
3. Lưu vào data/labeled_messages.csv và kích hoạt huấn luyện lại mô hình ML.
"""
import csv
import os
import sys
import logging
from datetime import datetime

# Thiết lập đường dẫn import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scripts.train_model import train_and_save_model

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# TẬP HỢP CÁC MẪU BIÊN CHUẨN XÁC ĐÃ ĐƯỢC GIÁM ĐỊNH
HARD_NEGATIVES = [
    # 1. Khuyến mại, nạp thẻ và chăm sóc khách hàng viễn thông chính thống (Viettel, Vina, Mobi)
    "[TB] NẠP THẺ LIỀN TAY, DATA XÀI NGAY! Tặng 20% giá trị tất cả thẻ nạp trong ngày 25/09/2026. Tiền KM sử dụng truy cập Internet trong 15 ngày. Nạp thẻ online tại các ví điện tử, ứng dụng thanh toán hoặc trên app Viettel Tammi tại https://vietteltammi.go.link/naptienkm20. Để nạp thẻ cào, Quý khách soạn NT [Mã thẻ] gửi 100. Chi tiết gọi 197 (phím 19, 0đ). Trân trọng.",
    "[TB] Viettel dành tặng Quý khách ưu đãi 20% giá trị thẻ nạp khi nạp tiền qua Viettel Money hoặc soạn tin NT [Mã thẻ] gửi 100. Chi tiết liên hệ 197 hoặc 198 (0đ).",
    "[TB] Viettel: Thue bao cua Quy khach da dang ky thanh cong goi ST120K (120.000d/30 ngay, co 60GB data toc do cao). De kiem tra luu luong soan KTTK gui 191. De huy gia han soan HUY ST120K gui 191.",
    "[TB] Quy khach duoc tang 1.000 diem Viettel++ nhan dip sinh nhat. Doi diem lay goi data 4G, phut goi hoac voucher mua sam tren My Viettel tai https://viettel.vn/viettelplus. CSKH: 18008098.",
    "[TB] Trai nghiem ung dung truyen hinh Viettel TV360 mien phi hoan toan data 4G xem bong da truc tiep tai https://tv360.vn hoac cai dat ung dung tren Google Play va App Store.",
    "[TB] Viettel thong bao: Nhap ma VIETTELPAY khi thanh toan cuoc Internet truyen hinh de duoc chiet khau 5% moi thang tren ung dung Viettel Money tai https://viettelmoney.vn.",
    "[TB] Soan tin KM gui 191 de tra cuu danh sach cac goi cuoc data 4G uu dai danh rieng cho thue bao cua ban. Chi tiet goi 198 (0d).",
    "Vinaphone thong bao: Khuyen mai 20% gia tri the nap toan quoc trong ngay vang hom nay. Tien KM su dung goi va nhan tin noi mang. Chi tiet lien he 18001091 (0d).",
    "Vinaphone: Quy khach da dang ky thanh cong goi BIG90 (90.000d/thang, co 30GB data toc do cao). De tra cuu dung luong con lai soan DATA gui 888. De huy soan HUY BIG90 gui 888.",
    "VNPT Vinaphone: Tang goi data 2GB toc do cao su dung trong 24h khi tai va dang nhap ung dung My VNPT lan dau tai https://my.vnpt.com.vn. Tong dai 18001091.",
    "MobiFone: Tang 20% gia tri the nap trong ngay hom nay cho tat ca thue bao tra truoc nap the qua app My MobiFone hoac vi dien tu. Chi tiet goi 9090 (200d/phut).",
    "MobiFone: Chuc mung Quy khach da dang ky thanh cong goi cuoc KC90 (90.000d/30 ngay, mien phi goi noi mang duoi 10 phut, 30GB data). Soan KT ALL gui 999 de kiem tra.",
    "MobiFone tran trong gui tang Quy khach co hoi trung thuong khi tham gia khao sat chat luong dich vu truc tuyen tai https://mobifone.vn. Ho tro: 18001090.",
    "Vietnamobile thong bao: Nap the tu 50.000d nhan ngay 10GB data su dung trong 7 ngay. Thong tin chi tiet lien he tong dai 789 (mien phi).",

    # 2. Tiếp thị, Voucher, Tri ân từ Sàn TMĐT và Ví điện tử (Shopee, Lazada, Tiki, Grab, MoMo)
    "Shopee: Tang ban Voucher giam 50.000d cho don hang tu 0d nhan ngay Sieu Sale 10.10. Mo app Shopee thu thap ma ngay tai https://shopee.vn/m/ma-giam-gia.",
    "Shopee: Don hang [NUMBER] cua ban da duoc giao thanh cong. Vui long danh gia san pham de nhan 200 Xu tren ung dung Shopee.",
    "Lazada: Ban co 1 ma giam gia 30k don tu 150k sap het han trong hom nay. Mo app Lazada de su dung truoc 23:59 tai https://lazada.vn.",
    "Lazada: Don hang [NUMBER] dang duoc shipper [NAME] van chuyen den ban. Vui long chuan bi so tien COD [MONEY] khi nhan hang.",
    "Tiki: Don hang cua ban da san sang giao. Ma don hang: [NUMBER]. Shipper TikiNOW se giao den trong vong 2 gio. Chi tiet theo doi tai https://tiki.vn.",
    "Tiki: Cam on ban da mua hang tai Tiki. Danh gia don hang de nhan diem thuong TikiXu va co hoi trung voucher 100k.",
    "Grab: Tang ban ma giam 30% toi da 50.000d cho chuyen GrabCar tiep theo khi thanh toan qua GrabPay. Chi tiet xem tai muc Uu dai tren app Grab.",
    "GrabFood: Uu dai com trua giam 40k cho don tu 100k tu cac quan an doi tac Grab Kitchen. Mo app dat mon ngay.",
    "MoMo: Chuc mung ban da nhan duoc goi qua tri an 100.000d thanh toan hoa don tien dien, tien nuoc thang nay. Mo vi MoMo tai https://momo.vn de xem chi tiet.",
    "MoMo: Giao dich thanh toan 45.000d tai Circle K thanh cong. So du vi hien tai: 520.000d. Chi tiet ma giao dich [NUMBER].",
    "ZaloPay: Tang voucher 20% nap the dien thoai cho tai khoan lien ket ngan hang thanh cong. Truy cap vi ZaloPay tren Zalo de nhan qua.",
    "ZaloPay: Giao dich chuyen tien den [NAME] so tien 200.000d thanh cong luc 14:30. Ma giao dich [NUMBER].",
    "Ahamove: Tai xe [NAME] so dien thoai 0987654321 dang giao don hang [NUMBER] den dia chi cua ban. Theo doi tai https://ahamove.com.",
    "Be Group: Nhan ngay uu dai beBike dong gia 10.000d cho 5 chuyen dau tien trong tuan. Mo app Be dat xe ngay.",

    # 3. Biến động số dư, giao dịch ngân hàng & Tiện ích
    "VCB: So du TK 001100482910 thay doi +3.500.000 VND luc 10:15 03/10/2026. So du: 18.250.000 VND. Ref: Luong thang 9 Cty ABC chuyen khoan.",
    "VCB: So du TK 001100482910 thay doi -150.000 VND luc 08:30 02/10/2026. So du: 14.750.000 VND. Ref: Thanh toan tien nuoc sach Ha Noi qua VCB Digibank.",
    "Techcombank: Quy khach da thanh toan thanh cong 420.000 VND cho hoa don tien dien EVN thang 9/2026 qua F@st Mobile. Ma GD [NUMBER].",
    "Techcombank thong bao: So du tai khoan thanh toan cua quy khach da thay doi +5.000.000 VND luc 16:45 tu NGUYEN VAN A.",
    "MBBank: TK 882019482910 phat sinh GD +1.200.000 VND luc 11:20 03/10/2026. So du kha dung: 6.840.000 VND.",
    "MBBank: Giao dich thanh toan hoc phi cho sinh vien [NAME] ma SV 20268492 tai Truong DH Quoc Gia da hoan tat. So tien: 4.500.000 VND.",
    "ACB: Thong bao phat sinh giao dich the Visa debit so duoi 4821 tai POS Sieu thi Co.opmart, so tien 380.000 VND.",
    "BIDV SmartBanking: Quy khach dang thuc hien mo tai khoan tiet kiem online ky han 6 thang, lai suat 5.2%/nam. Ma xac thuc OTP la: 492018.",
    "TPBank: Khoan vay tieu dung cua quy khach da den ky thanh toan truoc ngay 15/10. Vui long duy tri so du toi thieu de he thong tu dong trich no.",
    "VPBank: Chuc mung sinh nhat Quy khach! Tang ma giam gia 100.000d khi mua sam tai Shopee thanh toan bang the tin dung VPBank StepUp.",
    "Agribank: TK 1500205849201 thay doi +8.000.000 VND luc 09:10 ngay 01/10/2026. Noi dung: Thanh toan tien nong san.",
    "Sacombank: Giao dich thanh toan phi bao hiem nhan tho Prudential 12.000.000 VND qua Sacombank Pay da thuc hien thanh cong.",

    # 4. Tin nhắn Cảnh báo Bảo mật chính thống từ Ngân hàng (PSA Warnings)
    "Vietcombank khuyen cao: Tuyet doi KHONG chia se ma OTP, ten dang nhap, mat khau voi bat ky ai duoi moi hinh thuc. Ngan hang khong bao gio yeu cau thong tin bao mat nay.",
    "Sacombank canh bao: Ngan hang KHONG BAO GIO yeu cau quy khach doc ma OTP hoac truy cap lien ket la de xac thuc. Neu nghi ngo lua dao, goi ngay 1800585888.",
    "Techcombank canh giac: Canh giac voi cac cuoc goi mao danh co quan cong an, toa an yeu cau chuyen tien de chung minh trong sach. Tuyet doi khong lam theo.",
    "MBBank khuyen cao khach hang: De phong cac thu doan lua dao mao danh vien phi, hoc phi yeu cau chuyen khoan gap. Xac minh ky voi nha truong truoc khi chuyen.",
    "BIDV thong bao: Khach hang can trong voi thu doan lua dao tuyen cong tac vien online, chot don thu nhap cao tren mang xa hoi.",
    "ACB canh bao thu doan moi: Doi tuong gui tin nhan thong bao trung thuong va yeu cau nop phi truoc. Ngan hang khong to chuc cac chuong trinh doi phi nhan qua.",

    # 5. Thông báo Hành chính Nhà nước, Dịch vụ công, Thuế, Tiền điện nước
    "Cuc Thue TP Ha Noi thong bao: To khai thue thu nhap ca nhan quy 3/2026 cua ong/ba da duoc chap nhan. Tra cuu ket qua tai https://thuedientu.gdt.gov.vn.",
    "Cuc Thue TP.HCM: Thong bao nop le phi truoc ba dien tu cho phuong tien da duoc ghi nhan tren he thong thue dien tu.",
    "Bao hiem Xa hoi Viet Nam: Ho so huong che do thai san cua ban da duoc co quan BHXH quan/huyen giai quyet. Chi tiet tra cuu tren ung dung VssID.",
    "Bo Cong an: Cong dan co the thuc hien dang ky thuong tru, tam tru truc tuyen tren Cong dich vu cong Quoc gia tai https://dichvucong.bocongan.gov.vn.",
    "Bo Thong tin va Truyen thong: Nguoi dan hay canh giac voi cuoc goi tu dau so quoc te la, khong goi lai neu khong biet ro danh tinh.",
    "Tong Cong ty Dien luc mien Bac: Thong bao tien dien ky 10/2026 cua khach hang ma PA01HN12345 la 654.000d. Quy khach vui long thanh toan truoc ngay 15/10.",
    "Dien luc Ha Noi EVN HANOI: Thong bao lich tam ngung cung cap dien de bao tri luoi dien khu vuc Ngo 10 pho Chua Boc tu 08h00 den 12h00 ngay 05/10/2026.",
    "Cong ty Nuoc sach Ha Noi: Thong bao chi so dong ho nuoc thang nay cua quy khach la 18 m3, so tien thanh toan la 142.000 VND. Ho tro tong dai 19001540.",

    # 6. Thông báo Giao hàng Shipper chính thống (Legitimate Delivery)
    "GHTK thong bao: Shipper Nguyen Van Nam (0981234567) dang giao don hang [NUMBER] cho quy khach. So tien thu ho COD la 210.000 VND. Vui long de y dien thoai.",
    "GHN Express: Kien hang [NUMBER] cua shop My Pham Chinh Hang da duoc giao thanh cong. Cam on quy khach da su dung dich vu giao hang.",
    "VNPost: Buu pham [NUMBER] gui tu Buu dien TP Da Nang da den buu cuc phat. Buu ta se lien he giao hang trong buoi sang hom nay.",
    "J&T Express: Don hang [NUMBER] dang duoc phat den dia chi cua ban. Lien he tong dai 19001088 neu can ho tro hen gio giao lai.",
    "Shopee Xpress: Shipper SPX dang tren duong giao don hang [NUMBER]. Vui long kiem tra ten va ma don hang truoc khi nhan hang.",

    # 7. Tin nhắn Mã OTP thông thường (Giao mã an toàn, không yêu cầu gửi lại)
    "Ma xac thuc OTP cua ban la 629104, hieu luc trong 3 phut. Khong chia se ma nay voi bat ky ai de bao ve tai khoan ngan hang cua ban.",
    "Ma xac nhan dang nhap Zalo cua ban la 847291. Ma co hieu luc trong 5 phut. Tuyet doi khong cung cap cho nguoi khac.",
    "Google: Ma xac minh 2 buoc cua ban la G-849201. Khong chia se ma nay voi ai duoi bat ky ly do nao.",
    "Facebook: Ma xac nhan khoi phuc mat khau cua ban la 592817. Vui long nhap ma nay tren man hinh ung dung.",
    "TikTok: Ma xac minh tai khoan cua ban la 194820. Ma se het han sau 10 phut.",
    "Apple: Ma xac minh ID Apple cua ban la 482910. Khong chia se ma nay voi bat ky ai."
]

HARD_POSITIVES_SCAM = [
    # 1. Mạo danh viễn thông, đe dọa khóa sim, cập nhật sinh trắc học
    "[TB] Viettel: Thue bao cua ban chua cap nhat sinh trac hoc se bi khoa 2 chieu sau 24h. Cap nhat ngay tai http://viettel-sinhtrachoc.top de khong bi chan lien lac.",
    "[TB] Vinaphone: Thong bao thue bao cua quy khach bi phan anh phat tan tin nhan rac. Truy cap ngay http://vinaphone-xacthuc.vip de mo khoa sim.",
    "MobiFone: Phat hien thue bao chua dinh danh chinh chu theo nghi dinh moi. Soan tin nhan gui kem anh CCCD va truy cap http://mobifone-cskh.cc de hoan tat.",
    "Tong dai Viettel CSKH: Quy khach da dang ky goi cuoc 500k/thang thanh cong. Neu khong dang ky, goi ngay 0249998877 hoac bam link de huy cuoc.",

    # 2. Mạo danh ngân hàng và Lừa đảo tâm lý đảo ngược (Reverse OTP)
    "Vietcombank tran trong thong bao: Phat hien thiet bi la dang nhap tai khoan cua ban luc 03:15. Dang nhap ngay tai http://vcb-security.vip de xac minh va huy giao dich.",
    "Techcombank: Tai khoan cua ban bi tam khoa do nghi van giao dich bat thuong. Truy cap https://techcombank-mo-khoa.site de cap nhat lai ma PIN.",
    "MBBank: GD thanh toan 12.000.000 VND tai Dien May Xanh thanh cong. Neu khong phai ban giao dich, vui long truy cap http://mbbank-huy-don.top de huy.",
    "BIDV: Quy khach vua phat sinh lenh chuyen tien 25.000.000 VND. Neu khong thuc hien, bam vao http://bidv-hotro.vip de yeu cau hoan tien ngay lap tuc.",

    # 3. Lừa đảo tuyển dụng CTV, làm nhiệm vụ online, nạp tiền chốt đơn
    "Tuyen dung CTV danh gia san pham Shopee tai nha, luong 300k-800k/ngay, nhan tien ngay sau moi don hang, khong can kinh nghiem, lien he Zalo O981234567.",
    "Shopee tuyen nhan vien part time xu ly don hang online, thu nhap 15-20 trieu/thang, cong viec nhe nhang lam tren dien thoai. Inbox Telegram @tuyendungshopee.",
    "Cong ty TikTok Shop tuyen dung cong tac vien tha tim video kiem tien, moi luot tim nhan 50k, ngay kiem 500k de dang. Nhan tin Zalo de nhan viec ngay.",
    "Truong phong nhan su cty Lazada dang can tuyen gap 50 ban CTV danh gia shop, hoa hong tra ngay qua tai khoan. Khong coc, khong phi.",

    # 4. Giả danh Công an, Tòa án, Viện kiểm sát ngụy trang
    "C.o.n.g A.n T.P H.N t.r.i.e.u t.a.p c.o.n.g d.a.n lien quan duong day rua tien quy mo lon, yeu cau lien he Zalo O981234567 de lam viec gap.",
    "Toa an nhan dan thong bao ban co giay trieu tap ve hanh vi vi pham phap luat nghiem trong, goi ngay so dien thoai 02471098877 de nghe lenh bat giu.",
    "Bo Cong an thong bao tai khoan cua ban bi su dung trai phep vao muc dich buon lau. Chuyen toan bo tien vao tai khoan tam giu cua co quan dieu tra de giam dinh.",

    # 5. Trúng thưởng giả, xe máy, tặng quà mồi chài phí
    "Chuc mung chu nhan so dien thoai da trung thuong chiec xe may Honda SH 150i tu chuong trinh tri an khach hang. Chuyen khoan 2 trieu phi lam bien so vao STK de nhan xe.",
    "Ban da trung thuong so tien mat 100 trieu dong trong su kien Vong quay may man. Dong phi ho so 500k tai http://nhanqua-vietnam.top de duoc giai ngan.",

    # 6. Mạo danh Shipper trộm mã OTP hoặc phí lưu kho
    "Em la shipper giao hang day anh oi, do he thong dang loi anh doc giup em ma OTP 6 so gui ve may anh de em xac nhan hoan tat don hang cho anh nhe.",
    "Thong bao GHTK: Don hang cua ban chua thanh toan phi luu kho 20.000d, bam vao http://ghtk-trahang.cc de thanh toan neu khong kien hang se bi huy tieu huy.",

    # 7. Cờ bạc, Tài xỉu, Cho vay nặng lãi giả
    "Sieu no hu 888bet tang code 200k cho thanh vien moi dang ky, rut tien ve tai khoan ngan hang trong 30 giay khong can nap, truy cap http://nohu888.club.",
    "Cong ty tai chinh FE ho tro cho vay tien nhanh lai suat 0%, giai ngan 50 trieu trong 15 phut khong can gap mat. Nop phi bao hiem khoan vay de nhan tien."
]


def run_mining():
    data_path = 'data/labeled_messages.csv'
    logger.info("=== BẮT ĐẦU QUÁ TRÌNH KHAI PHÁ VÀ BỔ SUNG MẪU BIÊN (HARD NEGATIVE MINING) ===")

    # 1. Đọc dữ liệu hiện có
    existing_texts = set()
    rows = []
    fieldnames = ['message_id', 'date', 'text', 'label']

    if os.path.exists(data_path):
        with open(data_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            # Chuẩn hóa tên cột để xử lý BOM nếu có
            actual_fields = [fn.replace('\ufeff', '') for fn in reader.fieldnames]
            for row in reader:
                cleaned_row = {k.replace('\ufeff', ''): v for k, v in row.items()}
                existing_texts.add(cleaned_row.get('text', '').strip().lower())
                rows.append(cleaned_row)

    logger.info(f"Số lượng mẫu hiện có trong tập dữ liệu: {len(rows)}")

    # 2. Thêm Hard Negatives (An toàn - Label 0)
    added_hn = 0
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

    for i, text in enumerate(HARD_NEGATIVES, start=1):
        clean_text = text.strip()
        if clean_text.lower() not in existing_texts:
            existing_texts.add(clean_text.lower())
            rows.append({
                'message_id': f'HN_SAFE_{i:03d}',
                'date': now_str,
                'text': clean_text,
                'label': '0'
            })
            added_hn += 1

    # 3. Thêm Hard Positives (Lừa đảo đối kháng - Label 1)
    added_hp = 0
    for j, text in enumerate(HARD_POSITIVES_SCAM, start=1):
        clean_text = text.strip()
        if clean_text.lower() not in existing_texts:
            existing_texts.add(clean_text.lower())
            rows.append({
                'message_id': f'HP_SCAM_{j:03d}',
                'date': now_str,
                'text': clean_text,
                'label': '1'
            })
            added_hp += 1

    logger.info(f"Đã bổ sung thành công: {added_hn} mẫu biên an toàn (Hard Negatives)")
    logger.info(f"Đã bổ sung thành công: {added_hp} mẫu lừa đảo đối kháng (Hard Positives)")
    logger.info(f"Tổng số mẫu mới sau khi làm giàu: {len(rows)}")

    # 4. Ghi lại vào file CSV với UTF-8 SIG chuẩn
    with open(data_path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Đã lưu tập dữ liệu nâng cấp vào: {data_path}")

    # 5. Kích hoạt huấn luyện lại mô hình ML Ensemble
    logger.info("=== BẮT ĐẦU HUẤN LUYỆN LẠI MÔ HÌNH HỌC MÁY ENSEMBLE ===")
    train_and_save_model()
    logger.info("=== HOÀN TẤT QUÁ TRÌNH KHAI PHÁ VÀ TÁI HUẤN LUYỆN THÀNH CÔNG ===")


if __name__ == '__main__':
    run_mining()

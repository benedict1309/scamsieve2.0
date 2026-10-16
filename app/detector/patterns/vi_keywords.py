"""
Danh sach tu khoa/cum tu tieng Viet cho tung nhom dau hieu.

QUY UOC: tat ca tu khoa o day da duoc viet KHONG DAU, chu thuong -
vi luc so khop, van ban nguoi dung se duoc chuan hoa (xem text_utils.py)
truoc khi so sanh, nen tu khoa cung phai o cung dang.
"""

# ---- Nhom: Gia danh cong an / toa an / vien kiem sat ----
POLICE_COURT_KEYWORDS = [
    "cong an",
    "canh sat",
    "co quan dieu tra",
    "vien kiem sat",
    "toa an",
    "lenh bat",
    "lenh bat giu",
    "trieu tap",
    "giay trieu tap",
    "vu an",
    "dieu tra rua tien",
    "phap luat viet nam",
]

# ---- Nhom: Gia danh ngan hang / tong dai CSKH ----
BANK_KEYWORDS = [
    "ngan hang",
    "tong dai cham soc khach hang",
    "tong dai cskh",
    "the tin dung",
    "vietcombank",
    "techcombank",
    "bidv",
    "agribank",
    "sacombank",
    "acb bank",
    "vpbank",
    "mbbank",
    "vietinbank",
    "tpbank",
]

# ---- Nhom: Gia danh san thuong mai dien tu / don vi giao hang ----
ECOMMERCE_KEYWORDS = [
    "shopee",
    "lazada",
    "tiki",
    "sendo",
    "tiktok shop",
    "giao hang tiet kiem",
    "ghn express",
    "ghtk",
    "j&t express",
    "vnpost",
    "buu dien viet nam",
    "don hang cua ban dang",
]

# ---- Nhom: Gia danh co quan thue / BHXH / dien luc ----
UTILITY_KEYWORDS = [
    "co quan thue",
    "tong cuc thue",
    "chi cuc thue",
    "bao hiem xa hoi",
    "bhxh viet nam",
    "dien luc",
    "tap doan dien luc",
    "evn",
    "hoa don tien dien",
]

# ---- Cum tu the hien nguoi gui TU XUNG la dai dien to chuc ----
IDENTITY_CLAIM_MARKERS = [
    "toi la",
    "chung toi la",
    "can bo",
    "dai dien",
    "ben canh sat",
    "ben cong an",
    "thay mat co quan",
    "chung toi thong bao",
]

# ---- Cum tu huong thang toi nguoi nhan nhu tu phia to chuc goi den ----
# (dung ket hop voi tu khoa to chuc de tranh bao nham khi chi nhac ten
# to chuc mot cach thong thuong, vd tin PSA canh bao lua dao, thong bao
# hanh chinh chung...)
# LUU Y: KHONG dung "quy khach" o day - cum nay qua pho bien, ca tin nhan
# THAT tu ngan hang/nha mang cung dung, khong phan biet duoc that/gia.
CUSTOMER_TARGETING_MARKERS = [
    "tai khoan cua ban",
    "tai khoan cua quy khach",
    "tai khoan quy khach",
    "don hang cua ban",
    "thue bao cua ban",
    "hoa don cua ban",
]

# ---- Nhom: Ma OTP / ma xac thuc ----
# LUU Y: chi rieng viec nhac den "OTP" KHONG phai dau hieu lua dao - tin nhan
# that tu ngan hang/vi dien tu cung chua "Ma OTP: 123456" rat nhieu. Dau hieu
# that su la khi co nguoi YEU CAU nguoi nhan DOC/CUNG CAP ma do cho ho (ke
# gian mao danh nhan vien giao hang, ngan hang... goi dien/nhan tin xin ma).
OTP_KEYWORDS = [
    "ma otp",
    "otp",
    "ma xac thuc",
    "ma bao mat",
    "ma dung mot lan",
    "verification code",
    "one time password",
]

# LUU Y QUAN TRONG: KHONG dung cac cum chung chung nhu "cung cap ma" hay
# "chia se ma" - vi tin nhan CANH BAO AN TOAN that tu ngan hang cung hay
# viet dang "...se MAT TIEN neu cung cap Ma OTP cho bat ky ai" (phu dinh/
# canh bao, khong phai yeu cau that). Chi dung cac cum THE HIEN RO ai do
# dang truc tiep xin/yeu cau NGUOI DOC dua ma cho ho.
OTP_SHARE_REQUEST_MARKERS = [
    "doc giup",
    "doc gium",
    "doc ma otp",
    "doc ma xac thuc",
    "doc cho toi",
    "doc cho em",
    "doc cho anh",
    "doc cho chi",
    "cho toi ma",
    "cho toi xin ma",
    "cho em ma",
    "cho em xin ma",
    "cho anh ma",
    "cho chi ma",
    "cho xin ma",
    "nhan ma giup",
]

# ---- Nhom: Hoi thuc chuyen tien gap ----
# Cac cum tu nay duoc chon tu phan tich data/labeled_messages.csv - deu la
# cum XUAT HIEN CHINH XAC trong cac tin nhan lua dao that (vd gia danh
# nguoi than/ban be muon tien gap, gia danh ngan hang doa phong toa tai
# khoan...) va KHONG xuat hien trong tin nhan binh thuong/thong bao that
# trong bo du lieu mau, nen an toan de dung truc tiep (khong can ket hop
# them dieu kien nhu nhom OTP).
URGENT_TRANSFER_KEYWORDS = [
    "chuyen gap",
    "chuyen khoan gap",
    "chuyen tien gap",
    "chuyen ngay",
    "chuyen khoan ngay",
    "chuyen giup",
    "ket tien",
    "dang gap",
    "phong toa",
]

# ---- Nhom: Trung thuong / trung giai ----
# Phan tich data/labeled_messages.csv cho thay: tin nhan TIEP THI THAT tu
# telco/ngan hang hay dung kieu "CO HOI trung thuong..." (chua chac chan
# trung) va luon kem thu tuc dang ky binh thuong (soan tin, dang ky goi
# cuoc...). Tin nhan LUA DAO thi khang dinh "DA trung thuong/trung giai..."
# (mot cach chac nich, ngau nhien) VA kem theo yeu cau hanh dong de "nhan"
# giai (dong phi, dien thong tin, ky hop dong dien tu...). Vi vay CHI bao
# khi co CA HAI: nhac den trung thuong/trung giai VA co hanh dong nhan
# thuong/dong phi di kem - da kiem chung: ket hop nay khop 12/12 la tin
# lua dao that trong bo du lieu mau, khong co bao nham nao.
PRIZE_MENTION_KEYWORDS = [
    "trung thuong",
    "trung giai",
    "quay trung",
    "boc tham trung",
    "trung hu",
    "trung xe",
    "trung dien thoai",
    "trung iphone",
    "trung oto",
    "ky nghi duong",
    "chuyen du lich",
    "tour du lich",
    "phan thuong mien phi",
    "tang mien phi",
]

PRIZE_CLAIM_ACTION_MARKERS = [
    "dong phi",
    "phi nhan thuong",
    "phi ho so",
    "phi van chuyen",
    "nhan thuong tai",
    "de nhan thuong",
    "de nhan qua",
    "de nhan giai",
    "nhan qua tai",
    "nhan thuong luon",
    "nhan thuong ngay",
    "nhan qua ngay",
    "hoan tat thu tuc",
    "nhap thong tin nhan thuong",
    "ky hop dong dien tu",
    "ky hdong dien tu",
    "truy cap duong link",
    "truy cap link",
    "vao duong link",
    "vao link",
    "nhan phan thuong",
]

# ---- Nhom: Cai dat ung dung la (gia mao) ----
# LUU Y: bo du lieu mau CHUA CO nhieu vi du cho nhom nay (da phan tin nhac
# "cai dat ung dung" trong data la THAT - vd MoMo, Bluezone, i-Speed, eTax
# Mobile cua Bo TT&TT...), nen KHONG the dung 1 tu khoa chung chung "cai
# dat ung dung" (se bao nham rat nhieu). 2 vi du lua dao co that trong data
# deu dan link chua duoi ".apk" (vd bocongan.apk-chinhphu.cc) - nhung link
# nay THUC RA da bi nhom "URL dang ngo" bat duoc roi (do TLD .cc/.vip).
# Vi vay:
#   - "apk" duoc dung nhu 1 tin hieu doc lap, diem thap hon, vi day la
#     dinh dang file cai dat Android THUONG KHONG BAO GIO xuat hien trong
#     tin nhan chinh thong (App/Google Play khong bao gio yeu cau nguoi
#     dung tai file .apk roi tu cai, day la dau hieu bat thuong ro rang
#     du it gap trong mau du lieu nay).
#   - Cac cum con lai (APP_INSTALL_KEYWORDS + UNOFFICIAL_SOURCE_MARKERS)
#     la dua tren kien thuc pho bien ve lua dao (chua duoc kiem chung bang
#     data/labeled_messages.csv vi khong co vi du phu hop) - CHI bao khi co
#     CA HAI (vua co dong tu cai/tai ung dung, vua co cum the hien nguon
#     KHONG chinh thong), de giam toi da nguy co bao nham voi cac thong bao
#     cai app THAT (rat pho bien, vd tren).
APK_FILE_KEYWORDS = [
    "apk",
]

APP_INSTALL_KEYWORDS = [
    "cai dat ung dung",
    "tai ung dung",
    "cai ung dung",
    "tai app",
    "cai app",
]

UNOFFICIAL_SOURCE_MARKERS = [
    "khong qua ch play",
    "khong qua google play",
    "khong qua app store",
    "ngoai ch play",
    "ngoai google play",
    "khong co tren ch play",
    "khong co tren google play",
    "duong dan rieng",
    "file cai dat rieng",
    "tai truc tiep tu link",
    "cai dat truc tiep tu duong dan",
]

# ---- Nhom: Co bac, ca cuoc, tai xiu, game bai truc tuyen trai phep ----
GAMBLING_KEYWORDS = [
    "tai xiu",
    "song tai xiu",
    "song bac",
    "song bai",
    "ca cuoc",
    "ca do",
    "danh bac",
    "game bai",
    "game bai doi thuong",
    "no hu",
    "quay hu",
    "ban ca doi thuong",
    "xoc dia",
    "lo de online",
    "danh de online",
    "nha cai",
    "casino",
    "baccarat",
    "keo bong da",
    "ty le ca cuoc",
]

# ---- Nhom: Lua dao tuyen dung / Viec nhe luong cao / CTV lam nhiem vu ----
JOB_SCAM_INTENT_MARKERS = [
    "tuyen dung",
    "tuyen nhan vien",
    "tuyen ctv",
    "cong tac vien",
    "tuyen gap",
    "viec lam",
    "tim viec",
    "truong phong nhan su",
    "phong nhan su",
    "tuyen ban thoi gian",
    "tuyen part time",
    "tuyen nhan su",
    "cty tuyen",
    "cong ty tuyen",
]

JOB_SCAM_BAIT_MARKERS = [
    "viec nhe luong cao",
    "lam viec tai nha",
    "lam tai nha",
    "online tai nha",
    "luong ngay",
    "tra hang ngay",
    "luong duoc tra hang ngay",
    "tien luong duoc tra hang ngay",
    "thu nhap tu",
    "thu nhap moi ngay",
    "cong viec don gian",
    "khong can kinh nghiem",
    "hoa hong cao",
    "nhan hoa hong",
    "chot don",
    "tang tuong tac",
    "lam nhiem vu",
    "yeu cau do tuoi",
    "thu nhap on dinh",
]

JOB_SCAM_CONTACT_MARKERS = [
    "zalo",
    "telegram",
    "inbox",
    "lien he qua zalo",
    "lien he / zalo",
    "lien he zalo",
    "ket ban zalo",
    "nhan tin qua zalo",
]



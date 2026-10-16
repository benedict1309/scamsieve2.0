# BỘ TESTCASE KIỂM THỬ VÀ DEMO HỆ THỐNG P-SIEVE

Tài liệu tổng hợp các kịch bản thử nghiệm thực tế dành cho kiểm thử và báo cáo đồ án, phân chia rõ ràng giữa dữ liệu **AN TOÀN** và **LỪA ĐẢO / NGUY CƠ CAO**.

---

## 1. DỮ LIỆU TIN NHẮN (SMS)

### A. Nhóm Tin Nhắn An Toàn (Không Bị Báo Nhầm - Anti False Positive)

| Mã | Kịch bản | Nội dung tin nhắn mẫu | Kết quả mong đợi |
| :---: | :--- | :--- | :---: |
| **SMS-01** | Mã OTP ngân hàng thật | `Vietcombank: Ma OTP cua Quy khach la 849201 de xac thuc dang nhap eBank. KHONG chia se ma nay cho bat ky ai, ke ca nhan vien ngan hang.` | **AN TOÀN (Điểm rủi ro < 5%)** |
| **SMS-02** | Biến động số dư Techcombank | `Techcombank: Bien dong so du +2,500,000 VND vao 14:30 ngay 09/10/2026 tai POS Vinmart. So du kha dung: 15,820,000 VND.` | **AN TOÀN (Điểm rủi ro < 7%)** |
| **SMS-03** | Khuyến mãi nhà mạng Viettel | `[Viettel] Quy khach duoc tang 50% gia tri the nap khi nap tien qua Viettel Money truoc 24h ngay mai. Chi tiet soan KM gui 191.` | **AN TOÀN (Điểm rủi ro < 5%)** |
| **SMS-04** | Giao hàng Shipper COD | `Giao Hang Tiet Kiem: Don hang #89123 dang duoc shipper Nguyen Van B (0987123456) giao den ban. Tien thu ho COD: 145.000d.` | **AN TOÀN (Điểm rủi ro < 8%)** |
| **SMS-05** | Khuyến nghị tiết kiệm điện EVN | `EVN Ha Noi kinh bao: Tiet kiem dien la tiet kiem tien. Quy khach vui long tat cac thiet bi dien khong can thiet trong gio cao diem.` | **AN TOÀN (Điểm rủi ro < 5%)** |
| **SMS-06** | Mã xác thực tài khoản Google | `Google: Ma xac minh tai khoan Google cua ban la 629104. Khong chia se ma xac minh voi bat ky ai.` | **AN TOÀN (Điểm rủi ro < 5%)** |
| **SMS-07** | Trao đổi làm việc nhóm | `Toi nay 7h ca nhom hen gap o quan cafe gan truong nhe, nho mang theo laptop de lam bai tap lon.` | **AN TOÀN (Điểm rủi ro 0%)** |

### B. Nhóm Tin Nhắn Lừa Đảo / Giả Mạo

| Mã | Kịch bản lừa đảo | Nội dung tin nhắn mẫu | Kết quả mong đợi |
| :---: | :--- | :--- | :---: |
| **SMS-08** | Mạo danh ngân hàng dọa khóa tài khoản | `Vietcombank tran trong thong bao: Tai khoan cua ban bi tam khoa do vi pham bao mat. Vui long dang nhap ngay tai http://vietcombank-login-ebank.xyz de xac thuc trong 24h.` | **LỪA ĐẢO (Điểm rủi ro > 95%)** |
| **SMS-09** | Giả danh Công an điều tra rửa tiền | `Chao anh/chi, toi la can bo Cuc Canh sat Dieu tra toi pham Bo Cong An. Anh/chi dang lien quan den du an rua tien xuyen quoc gia, yeu cau co mat tai co quan hoac chuyen tien vao tai khoan tam giu de chung minh trong sach.` | **LỪA ĐẢO (Điểm rủi ro > 90%)** |
| **SMS-10** | Tuyển dụng online làm nhiệm vụ nạp tiền | `Tuyen dung Shopee: Lam viec online tai nha, xem video danh gia san pham nhan luong 300k - 800k/ngay. Khong can kinh nghiem, thanh toan ngay qua tai khoan ngan hang. Inbox Zalo 0912345678.` | **LỪA ĐẢO (Điểm rủi ro > 85%)** |
| **SMS-11** | Chèn ký tự né kiểm duyệt (Homoglyphs/Teencode) | `C.o.n.g A.n T.P t.r.i.e.u t.a.p gap lien quan vu an hinh su. Yeu cau c.k gap vao s.t.k tam giu de phuc vu dieu tra.` | **LỪA ĐẢO (De-obfuscation phát hiện)** |
| **SMS-12** | Bẫy trúng thưởng xe máy SH tri ân | `Chuc mung Quy khach may man trung thuong 01 xe may SH 150i tu chuong trinh tri an khach hang. Truy cap ngay http://quatang-triandacbiet.xyz de nhan giai.` | **LỪA ĐẢO (Điểm rủi ro > 95%)** |
| **SMS-13** | Đe dọa khóa SIM viễn thông | `Tong dai VNP-CSKH: Thue bao cua quy khach se bi khoa hai chieu trong 2 gio toi do chua chuan hoa thong tin. Lien he ngay hotline 0247300123 de duoc huong dan mo khoa.` | **LỪA ĐẢO / NGUY CƠ CAO** |

---

## 2. DỮ LIỆU ĐƯỜNG DẪN WEB (URL)

### A. Nhóm URL An Toàn Chính Thống

| Mã | Đơn vị chủ quản | Đường dẫn URL | Cơ chế nhận diện | Điểm an toàn |
| :---: | :--- | :--- | :--- | :---: |
| **URL-01** | Cổng Dịch vụ công Quốc gia | `https://dichvucong.gov.vn` | Tên miền cơ quan Nhà nước (`.gov.vn`) | **100/100 AN TOÀN** |
| **URL-02** | Ngân hàng Vietcombank | `https://www.vietcombank.com.vn` | Danh bạ bảo hộ chính thống | **100/100 AN TOÀN** |
| **URL-03** | Ngân hàng Techcombank | `https://techcombank.com` | Danh bạ bảo hộ chính thống | **100/100 AN TOÀN** |
| **URL-04** | Sàn TMĐT Shopee Việt Nam | `https://shopee.vn` | Danh bạ bảo hộ chính thống | **100/100 AN TOÀN** |
| **URL-05** | Báo điện tử VnExpress | `https://vnexpress.net` | Danh bạ cơ quan báo chí | **100/100 AN TOÀN** |
| **URL-06** | Tìm kiếm Google | `https://www.google.com` | Danh bạ toàn cầu xác thực | **100/100 AN TOÀN** |

### B. Nhóm URL Lừa Đảo & Bẫy Kỹ Thuật

| Mã | Thủ đoạn tấn công | Đường dẫn URL | Dấu hiệu vi phạm phát hiện | Kết luận |
| :---: | :--- | :--- | :--- | :---: |
| **URL-07** | Hoán đổi chữ cái (Typosquatting) | `http://veitcombank.net/login` | Tương đồng 92.6% Vietcombank (`ie` thành `ei`) | **LỪA ĐẢO / MẠO DANH** |
| **URL-08** | Bỏ sót chữ cái (Omission Squatting) | `http://techcombnk.com/ebank` | Tương đồng 96.0% Techcombank (thiếu chữ `a`) | **LỪA ĐẢO / MẠO DANH** |
| **URL-09** | Khử dấu gạch nối (Hyphenation Squatting) | `https://viet-com-bank.xyz/portal` | Khử gạch nối trùng khớp tên ngân hàng | **LỪA ĐẢO / MẠO DANH** |
| **URL-10** | Thay thế thị giác (Visual / rn thành m) | `http://vietcornbank-ebank.xyz/otp` | Thay thế `rn` thành `m` + TLD rủi ro cao `.xyz` | **LỪA ĐẢO / MẠO DANH** |
| **URL-11** | Danh sách đen mã độc (Threat Intel) | `https://www.musictoyourhome.com` | Nằm trong cơ sở dữ liệu URLhaus / OpenPhish | **LỪA ĐẢO / MÃ ĐỘC** |
| **URL-12** | Bẫy chuyển hướng ngầm (Open Redirect) | `https://google.com/url?q=http://scam-bank.top` | Phát hiện tham số chuyển hướng tới tên miền lạ | **CẢNH BÁO NGUY HIỂM** |
| **URL-13** | Giả tạo chứng chỉ đăng nhập (Credential @) | `https://vietcombank.com.vn@scam-server.xyz/login` | Kẻ gian dùng tiền tố `@` nhằm đánh lừa thị giác | **LỪA ĐẢO / NGUY CƠ CAO** |
| **URL-14** | Sử dụng địa chỉ IP trực tiếp | `http://185.220.101.5/ebank` | Sử dụng IP trực tiếp thay vì DNS hợp pháp | **CẢNH BÁO NGUY HIỂM** |

---

## 3. DỮ LIỆU SỐ ĐIỆN THOẠI (SĐT)

### A. Nhóm Số Điện Thoại An Toàn

| Mã | Loại thuê bao | Số điện thoại mẫu | Hệ thống nhận diện | Kết quả |
| :---: | :--- | :--- | :--- | :---: |
| **TEL-01** | Tổng đài CSKH Viettel miễn cước | `18008098` | Đầu số dịch vụ miễn cước 1800 hợp lệ | **AN TOÀN** |
| **TEL-02** | Hotline Ngân hàng Vietcombank | `1900545413` | Đầu số tổng đài dịch vụ 1900 chính thống | **AN TOÀN** |
| **TEL-03** | Số cố định cơ quan nội địa | `02438255555` | Mã vùng Hà Nội (024), đầu số cố định nội địa | **AN TOÀN** |
| **TEL-04** | Thuê bao di động Viettel thông thường | `0988123456` | Thuê bao di động cá nhân hợp lệ | **AN TOÀN** |

### B. Nhóm Số Điện Thoại Nguy Cơ Cao / Lừa Đảo

| Mã | Kịch bản rủi ro | Số điện thoại mẫu | Cơ chế nhận diện | Kết quả |
| :---: | :--- | :--- | :--- | :---: |
| **TEL-05** | Đầu số vệ tinh quốc tế hút cước | `+88216500123` | Mã quốc gia vệ tinh giá cước cực cao (Inmarsat) | **CẢNH BÁO NGUY HIỂM** |
| **TEL-06** | Đầu số châu Phi nháy máy dụ gọi lại | `+25299123456` | Mã quốc gia Somalia (+252), bẫy cước viễn thông | **CẢNH BÁO ĐẦU SỐ LẠ** |
| **TEL-07** | Ngụy trang số 0 bằng chữ cái 'O' | `O987123456` | Tự động chuẩn hóa chữ 'O' thành số '0' | **ĐỐI SOÁT CHÍNH XÁC** |
| **TEL-08** | Số đã bị người dân tố cáo lừa đảo | *(Số đã nhập trong trang Báo cáo)* | Tra cứu trực tiếp SQLite Blacklist / Reports | **ĐÃ BỊ TỐ CÁO** |

---

## 4. KỊCH BẢN DEMO ĐỀ XUẤT (3 PHÚT TRÌNH BÀY)

1. **Phút 1 - Trình diễn kiểm tra Tin nhắn (SMS):**
   * Sao chép mẫu **SMS-01** (OTP Vietcombank thật) $\to$ Hệ thống báo **An toàn** (rủi ro < 5%), giải thích: *"Mô hình không bị bắt vẹt từ khóa OTP nhờ tập dữ liệu Hard Negatives đối kháng"*.
   * Sao chép mẫu **SMS-08** (Vietcombank dọa khóa thẻ) $\to$ Hệ thống báo **Lừa đảo** (rủi ro 99%).
2. **Phút 2 - Trình diễn kiểm tra Đường dẫn (URL):**
   * Nhập **URL-02** (`vietcombank.com.vn`) $\to$ Điểm an toàn **100/100**.
   * Nhập **URL-07** (`veitcombank.net`) $\to$ Hệ thống chỉ rõ lỗi **Typosquatting hoán đổi chữ cái**.
   * Nhập **URL-11** (`musictoyourhome.com`) $\to$ Hệ thống kích hoạt **Threat Intelligence Blacklist**.
3. **Phút 3 - Trình diễn Tiện ích mở rộng (Chrome Extension):**
   * Mở Extension trên trình duyệt: Thể hiện tốc độ phản hồi tính bằng mili-giây, bảng 21 tiêu chí an toàn và khối đánh giá chi tiết với thiết kế tối giản, tinh tế.


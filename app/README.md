# ScamSieve

ScamSieve giúp người dùng phát hiện dấu hiệu lừa đảo trong chat, email và URL:
dán nội dung cần kiểm tra, hệ thống trả về điểm rủi ro 0–100, mức nguy cơ,
các dấu hiệu đáng nghi và hướng dẫn xử lý an toàn.

> ScamSieve là công cụ hỗ trợ tham khảo, **không thay thế** cơ quan chức năng
> (công an, ngân hàng, tòa án...).

## Công nghệ sử dụng

- Backend: Python + FastAPI
- Giao diện: Jinja2 + HTML/CSS + JavaScript/HTMX tối thiểu (không React/Vue/Flutter)
- Database: SQLAlchemy + SQLite (dev) / PostgreSQL (production)
- Auth: Session-cookie (HttpOnly)

## Yêu cầu

- Python 3.11 trở lên đã cài trên Windows ([tải tại đây](https://www.python.org/downloads/))
- (Tùy chọn) Git để clone mã nguồn

## Cài đặt và chạy trên Windows

Mở **PowerShell** hoặc **Command Prompt** tại thư mục dự án, chạy lần lượt:

1. Tạo môi trường ảo:

   ```
   python -m venv venv
   ```

2. Kích hoạt môi trường ảo:

   - PowerShell:
     ```
     venv\Scripts\Activate.ps1
     ```
     (Nếu PowerShell báo lỗi không cho chạy script, mở PowerShell với quyền Admin
     và chạy: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, gõ `Y` để xác nhận,
     rồi thử lại bước 2.)
   - Command Prompt (cmd):
     ```
     venv\Scripts\activate.bat
     ```

   Thấy `(venv)` xuất hiện ở đầu dòng lệnh là đã kích hoạt thành công.

3. Cài các thư viện cần thiết:

   ```
   pip install -r requirements.txt
   ```

4. Tạo file cấu hình `.env` từ file mẫu:

   ```
   copy .env.example .env
   ```

5. Chạy server:

   ```
   uvicorn app.main:app --reload
   ```

6. Mở trình duyệt và truy cập: http://127.0.0.1:8000

   Database (`scamsieve.db`) sẽ tự động được tạo trong thư mục dự án ở lần chạy đầu tiên.

## Mở và chạy bằng VS Code

Project đã có sẵn cấu hình trong thư mục `.vscode/` (không cần PyCharm):

1. Mở VS Code → File → Open Folder... → chọn thư mục `scamsieve` (thư mục vừa giải nén).
2. Lần đầu mở, VS Code sẽ gợi ý cài extension "Python" (Microsoft) — bấm **Install**.
3. Đã tạo venv theo hướng dẫn ở trên chưa? Nếu rồi, bấm `Ctrl+Shift+P` → gõ **"Python: Select Interpreter"** → chọn interpreter nằm trong `.\venv\Scripts\python.exe`.
4. Vào tab **Run and Debug** (biểu tượng hình con bọ ở thanh bên trái, hoặc `Ctrl+Shift+D`), chọn 1 trong 3 cấu hình có sẵn ở góc trên:
   - **ScamSieve: chạy server (uvicorn)** — chạy web server, bấm F5 để bắt đầu, có thể đặt breakpoint để debug.
   - **ScamSieve: chạy tất cả test** — chạy toàn bộ unit test.
   - **ScamSieve: đánh giá detector** — chạy script đánh giá trên dataset.
5. Ngoài ra có thể bấm vào icon "Testing" (hình ống nghiệm) ở thanh bên trái để xem/chạy từng test riêng lẻ mà không cần gõ lệnh.

## Cấu trúc dự án

```
app/
├── main.py          # Khởi tạo FastAPI app
├── config.py         # Đọc biến môi trường từ .env
├── database.py        # Engine, Session, Base (SQLAlchemy)
├── models/              # Các bảng dữ liệu (User, Blacklist, Report, ScanHistory)
├── routers/               # Các route (trang, quét, lịch sử, báo cáo, admin...)
├── services/                # Logic nghiệp vụ (blacklist_service.py tra cứu SĐT; thêm dần ở các bước sau)
├── detector/                  # Bộ phát hiện lừa đảo rule-based (sẽ bổ sung ở Bước 4)
├── templates/                   # Giao diện Jinja2
└── static/                        # CSS, JS, ảnh
tests/                              # Unit test
```

## Trạng thái hiện tại

- [x] Bước 1: Kiến trúc & cấu trúc thư mục
- [x] Bước 2: Thiết kế schema database (User, Blacklist, Report, ScanHistory)
- [x] Bước 3: Khung FastAPI chạy được (trang chủ + kết nối DB)
- [x] Bước 4: Module rule-based — ĐỦ 7/7 nhóm. 6 nhóm THUẦN TÚY (không cần
  DB, chạy được cả trong `scripts/evaluate_detector.py`, gọi qua
  `detect_all()`):
  - "giả danh cơ quan/tổ chức" (4 kịch bản)
  - "yêu cầu đọc/cung cấp mã OTP" (chỉ báo khi VỪA nhắc OTP VỪA có cụm xin/
    yêu cầu đọc mã — tránh báo nhầm hàng loạt tin OTP thật của ngân hàng)
  - "hối thúc chuyển tiền gấp" (giả danh người thân/bạn bè cần tiền gấp,
    đe dọa phong tỏa tài khoản...)
  - "URL đáng ngờ" (phát hiện link dùng đuôi tên miền rẻ, dễ đăng ký nặc
    danh như .top/.cc/.vip/.online/.club/.xyz/.icu/.shop/.life/.biz/.space/
    .buzz/.run/.asia — không dựa vào .com/.net/.me vì các đuôi này bị dùng
    lẫn cả trong tin thật)
  - "trúng thưởng giả" (chỉ báo khi VỪA khẳng định đã trúng thưởng/trúng
    giải VỪA có yêu cầu đóng phí/hoàn tất thủ tục nhận — tránh báo nhầm
    tin tiếp thị thật kiểu "CƠ HỘI trúng thưởng..." không đòi phí)
  - "cài app lạ" — 2 tầng: (1) link/file đuôi `.apk` (tín hiệu độc lập, đã
    kiểm chứng sạch 2/2 trong dữ liệu mẫu), (2) có động từ cài/tải ứng dụng
    KÈM cụm từ "không qua CH Play/App Store..." (⚠️ CHƯA kiểm chứng bằng dữ
    liệu thực tế — dữ liệu mẫu không có ví dụ phù hợp, chỉ dựa trên kiến
    thức chung về lừa đảo, ghi rõ trong `explanation` trả về)

  ...VÀ 1 nhóm rule CẦN DATABASE (đặt ở `app/services/blacklist_service.py`
  thay vì `app/detector/rules.py`, vì cần truy vấn bảng `Blacklist`):
  - "tra cứu blacklist số điện thoại" — `app/detector/phone_utils.py` trích
    xuất các chuỗi giống số điện thoại trong nội dung (hỗ trợ nhiều định
    dạng: số thuần, có khoảng trắng/gạch ngang, dạng quốc tế +84), rồi
    `blacklist_service.check_blacklist_phone(text, db)` tra trong bảng
    `Blacklist` (content_type=PHONE). CHƯA được gắn vào `detect_all()` vì
    hàm đó cố tình giữ thuần túy/không DB — sẽ được gọi CÙNG với
    `detect_all()` ở router quét nội dung (Bước 5), rồi gộp điểm bằng
    `scorer.total_score()`.

  52 unit test (tăng từ 41 — thêm `TestFakePrize` và `TestAppInstall` vào
  `tests/test_detector.py`). Đánh giá trên `data/labeled_messages.csv`
  (2991 tin thật, có nhãn): precision ~99.7%, recall ~36.8% ở mức "any tín
  hiệu" (tăng nhẹ từ 36.1% — nhóm trúng thưởng/apk đóng góp ít vì phần lớn
  case ".apk" đã trùng với nhóm URL); ở mức cảnh báo MEDIUM/HIGH thực sự:
  recall 2.8%, precision 100% (tăng từ 1.8% — vài tin nay đủ nhiều tín hiệu
  cộng dồn để vượt ngưỡng). 1 FP tồn đọng từ nhóm `imp_ecommerce` (tin Tiki
  gửi mã xác minh đăng ký) — cần xem lại sau. Nhóm "cài app lạ" (nhánh
  không-chính-thống) và độ phủ tổng thể (36.8%/2.8%) còn thấp, cần thêm dữ
  liệu/rule để cải thiện recall ở các bước sau nếu có thời gian.
- [x] Bước 5: Giao diện quét nội dung / trang kết quả
  - `app/routers/scan.py`: `GET /scan` (form nhập), `POST /scan` (chạy
    `detect_all()` + `check_blacklist_phone()`, gộp điểm bằng
    `score_and_classify()`, hiển thị kết quả)
  - `templates/scan.html`, `templates/scan_result.html` — banner màu theo
    mức rủi ro (xanh/vàng/đỏ), liệt kê từng dấu hiệu khớp kèm giải thích,
    lời khuyên hành động cụ thể theo từng mức (LOW/MEDIUM/HIGH)
  - CHƯA đăng nhập, CHƯA lưu vào `ScanHistory` (bảng đó bắt buộc
    `user_id`, sẽ nối vào khi làm xong đăng nhập ở Bước 6)
  - 5 test tích hợp mới (`tests/test_scan_router.py`, dùng
    `fastapi.testclient.TestClient`, cần thêm `httpx` vào
    `requirements.txt`) — tổng 57 unit/integration test, đã tự chạy thử
    thủ công qua `curl` để xác nhận giao diện hoạt động đúng
  - Giao diện đã được thiết kế lại (`app/static/css/style.css`) theo
    phong cách "cảnh báo an ninh mạng" lấy cảm hứng từ ChongLuaDao: nền
    xanh đen/đen sẫm, điểm nhấn cyan-trắng, tiêu đề dùng
    `-webkit-text-stroke` để tạo viền chữ đậm, KHÔNG dùng icon/emoji ở
    bất kỳ đâu (kể cả tam giác mặc định của thẻ `<details>` cũng đã bị
    ẩn bằng CSS). Đã render thử bằng Playwright để kiểm tra trực quan.
- [ ] Bước 6: Tài khoản người dùng, lịch sử quét, báo cáo, trang admin
- [ ] Bước 7: Checklist kiểm thử, dữ liệu demo, hướng dẫn deploy

## Ghi chú kỹ thuật

- Bảng trong database được tạo tự động bằng `Base.metadata.create_all()` khi
  khởi động app (phù hợp giai đoạn phát triển). Alembic (quản lý migration)
  sẽ được bổ sung khi dự án chuẩn bị triển khai lên PostgreSQL.
- Không sử dụng API AI trả phí, API bên ngoài, hoặc dữ liệu blacklist từ bên
  thứ ba nếu chưa được thống nhất trong nhóm.

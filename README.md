# Scam-Sieve

Hệ thống phát hiện lừa đảo trực tuyến cho người dùng Việt Nam — phân tích tin nhắn SMS, URL và số điện thoại, trả về điểm rủi ro 0–100, mức cảnh báo và hướng dẫn xử lý cụ thể.

> Scam-Sieve là công cụ hỗ trợ tham khảo, **không thay thế** cơ quan chức năng (công an, ngân hàng, tòa án...).

---

## Tính năng chính

- **Phân tích đa lớp**: kết hợp rule-based heuristic, mô hình ML (LightGBM + PhoBERT), và AI ngôn ngữ (Gemini / Groq) để đánh giá rủi ro
- **Phát hiện lừa đảo SMS**: nhận diện giả danh cơ quan, yêu cầu OTP, hối thúc chuyển tiền, trúng thưởng giả, cài app lạ
- **Phân tích URL**: phát hiện domain giả mạo thương hiệu (typosquatting, homoglyph, combosquatting), IP trực tiếp, redirect lạ, DGA domain
- **Tình báo số điện thoại**: nhận diện đầu số VoIP cố định ảo (Digitel, GMobile), sim rác, hotline chính thống
- **Threat Intelligence**: tích hợp URLhaus + OpenPhish cập nhật định kỳ, blacklist nội bộ
- **OCR từ ảnh chụp màn hình**: trích xuất nội dung từ ảnh để kiểm tra
- **Extension trình duyệt**: kiểm tra URL ngay khi duyệt web (Chrome/Edge)
- **Giao diện web**: không cần đăng nhập, nhập nội dung và nhận kết quả ngay lập tức

---

## Kiến trúc hệ thống

```
Nội dung đầu vào (SMS / URL / SĐT)
        │
        ▼
┌─────────────────────────────────────────┐
│          Lớp 1: Heuristic Engine        │  ← rule-based, từ khóa, pattern
│  rules.py + heuristics.py + scorer.py  │
└────────────────────┬────────────────────┘
                     │ unified_risk_score
        ▼
┌─────────────────────────────────────────┐
│          Lớp 2: ML Models               │
│  ml_model.joblib  (SMS classifier)      │  ← TF-IDF + LightGBM
│  url_lgbm_model.joblib (URL classifier) │  ← 30+ URL features + LightGBM
│  phobert_head.joblib (NLP head)         │  ← PhoBERT fine-tuned
└────────────────────┬────────────────────┘
                     │
        ▼
┌─────────────────────────────────────────┐
│        Lớp 3: AI Cross-Verification     │
│  Gemini AI / Groq LLM                   │  ← phân tích ngữ nghĩa sâu
│  + Guardrail đồng bộ kết quả           │  ← không bao giờ mâu thuẫn lớp 1
└────────────────────┬────────────────────┘
                     │
        ▼
        Kết quả: Điểm rủi ro + Phân loại + Khuyến nghị
```

---

## Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Backend | Python 3.12 + FastAPI |
| Giao diện | Jinja2 + HTML/CSS (không React/Vue) |
| Database | SQLAlchemy + SQLite |
| ML Models | LightGBM, scikit-learn (TF-IDF) |
| NLP | PhoBERT (VinAI) |
| AI Cloud | Google Gemini API + Groq API |
| Threat Intel | URLhaus, OpenPhish |
| Extension | Chrome Extension (Manifest V3) |
| Testing | pytest (148 tests) |

---

## Cài đặt và chạy

### Yêu cầu

- Python 3.11 trở lên
- Git

### Các bước

**1. Clone về máy:**
```bash
git clone https://github.com/QuanVuVan/Scam-Sieve.git
cd Scam-Sieve
```

**2. Tạo và kích hoạt môi trường ảo:**
```bash
python -m venv venv

# PowerShell
venv\Scripts\Activate.ps1

# Command Prompt
venv\Scripts\activate.bat
```

> Nếu PowerShell báo lỗi policy, chạy: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

**3. Cài thư viện:**
```bash
pip install -r requirements.txt
```

**4. Tạo file `.env`:**
```bash
copy .env.example .env
```

Mở file `.env` và điền API key:
```env
DATABASE_URL=sqlite:///./scamsieve.db
SECRET_KEY=your-secret-key-here
GEMINI_API_KEY=your-gemini-api-key
GROQ_API_KEY=your-groq-api-key
DEBUG=True
```

- Gemini API key: https://aistudio.google.com/app/apikey
- Groq API key: https://console.groq.com/keys

**5. Chạy server:**
```bash
uvicorn app.main:app --reload
```

Truy cập: **http://127.0.0.1:8000**

Database `scamsieve.db` tự động tạo ở lần chạy đầu.

---

## Cấu trúc thư mục

```
Scam-Sieve/
├── app/
│   ├── main.py                    # Khởi tạo FastAPI app
│   ├── config.py                  # Đọc biến môi trường từ .env
│   ├── database.py                # SQLAlchemy engine & session
│   ├── models/                    # Schema database (Blacklist, Report, ScanHistory...)
│   ├── routers/
│   │   ├── scan.py                # POST /scan, /api/gemini-consult, /api/ocr-extract
│   │   ├── api_v1.py              # REST API /api/v1/...
│   │   ├── reports.py             # Báo cáo cộng đồng
│   │   └── pages.py              # Trang tĩnh
│   ├── services/
│   │   ├── gemini_service.py      # Tích hợp Gemini AI + Groq
│   │   ├── blacklist_service.py   # Tra cứu blacklist SĐT/URL
│   │   ├── threat_feed_service.py # Cập nhật URLhaus + OpenPhish
│   │   └── domain_intel.py        # WHOIS + domain intelligence
│   ├── detector/
│   │   ├── rules.py               # 7 nhóm rule-based lừa đảo
│   │   ├── heuristics.py          # 21 tiêu chí heuristic URL
│   │   ├── scorer.py              # Tổng hợp điểm rủi ro
│   │   ├── phone_utils.py         # Phân tích đầu số điện thoại
│   │   ├── phobert_classifier.py  # PhoBERT inference
│   │   ├── url_ml_classifier.py   # LightGBM URL classifier
│   │   └── guardrails.py          # Đồng bộ kết quả AI với heuristic
│   ├── templates/                 # Giao diện Jinja2
│   └── static/                    # CSS, ảnh
├── data/
│   ├── labeled_messages.csv       # Dataset SMS có nhãn
│   ├── url_phishing_dataset.csv   # Dataset URL phishing
│   └── url_dataset_industrial.csv # Dataset URL từ nguồn thực tế
├── extension/                     # Chrome Extension
├── scripts/                       # Train model, đồng bộ dữ liệu
├── tests/                         # 148 unit & integration tests
├── .env.example                   # Mẫu cấu hình
├── requirements.txt
└── start_server.bat               # Chạy nhanh trên Windows
```

---

## Chạy test

```bash
pytest -v
```

Kết quả: **148 passed**

---

## Cài đặt Extension trình duyệt

1. Mở Chrome → `chrome://extensions/`
2. Bật **Developer mode** (góc phải trên)
3. Bấm **Load unpacked** → chọn thư mục `extension/`
4. Extension tự động kiểm tra URL khi duyệt web

> Extension cần server đang chạy tại `http://127.0.0.1:8000`

---

## Lưu ý bảo mật

- File `.env` chứa API key — **không được đẩy lên GitHub** (đã có trong `.gitignore`)
- Các file model `.joblib` không có trong repo (kích thước lớn) — cần train lại bằng script trong `scripts/`
- Hệ thống sử dụng API Gemini và Groq — cần key hợp lệ để tính năng AI hoạt động; hệ thống rule-based vẫn hoạt động khi không có key

---

## Tác giả

Dự án đại học — Hệ thống Phát hiện Lừa đảo Trực tuyến P-Sieve

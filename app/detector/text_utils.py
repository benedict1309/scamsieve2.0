import re
import unicodedata
import logging

logger = logging.getLogger(__name__)


class TextPreprocessor:
    def __init__(self):
        # Ký tự tàng hình / zero-width space
        self.zws_pattern = re.compile(r'[\u200B-\u200D\uFEFF\u200E\u200F\u00AD]')

        # Bảng ánh xạ Homoglyphs (Cyrillic & ký tự nhìn giống sang chữ cái Latinh)
        self.homoglyph_map = str.maketrans({
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'M': 'M', 'Н': 'H', 'О': 'O',
            'Р': 'P', 'С': 'C', 'Т': 'T', 'X': 'X', 'У': 'Y',
            '@': 'a', '!': 'i', '$': 's',
        })

        # Teencode / viết tắt phổ biến trong tin nhắn lừa đảo tài chính tiếng Việt
        self.teencode_map = {
            r'\bck\b': 'chuyen khoan',
            r'\bstk\b': 'so tai khoan',
            r'\btk\b': 'tai khoan',
            r'\bnh\b': 'ngan hang',
            r'\bsdt\b': 'so dien thoai',
            r'\bsđt\b': 'so dien thoai',
            r'\bkh\b': 'khach hang',
            r'\bkm\b': 'khuyen mai',
            r'\btr\b': 'trieu',
            r'\bk\b': 'nghin',
            r'\bđt\b': 'dien thoai',
            r'\bxn\b': 'xac nhan',
            r'\bcv\b': 'cong viec',
            r'\bctv\b': 'cong tac vien',
            r'\blh\b': 'lien he',
        }

    def _clean_token_noise(self, token: str) -> str:
        """
        Khử ký tự chèn lén bên trong 1 từ:
        - C.o.n.g -> Cong
        - t-r-i-e-u -> trieu
        - trúúúng -> trúng (thu gọn ký tự kéo dài)
        """
        # Khử dấu phân tách chen giữa các chữ cái
        cleaned = re.sub(r'(?<=\w)[.\-_/\\,;:*^~+~|](?=\w)', '', token)
        # Thu gọn ký tự lặp 3 lần trở lên (trúúúng -> trúng, quààà -> quà)
        cleaned = re.sub(r'([^\d\s])\1{2,}', r'\1', cleaned)
        return cleaned

    def normalize(self, text: str) -> str:
        """
        Làm sạch và chuẩn hóa văn bản đầu vào:
        1. Unicode NFKC
        2. Loại bỏ Zero-width space
        3. Khử dấu chấm/gạch nối/ký tự chen giữa các chữ cái trong từ
        4. Ánh xạ Homoglyphs (Cyrillic, Leetspeak)
        5. Giải nén Teencode giao dịch
        6. Chuẩn hóa khoảng trắng và đưa về chữ thường
        """
        if not isinstance(text, str) or not text.strip():
            return ""
        try:
            # 1. NFKC
            normalized = unicodedata.normalize('NFKC', text)
            # 2. Xóa ZWS
            cleaned = self.zws_pattern.sub('', normalized)
            # 3. Khử ký tự chen lén trong từng token
            tokens = cleaned.split()
            cleaned_tokens = [self._clean_token_noise(t) for t in tokens]
            cleaned = " ".join(cleaned_tokens)
            # 4. Homoglyphs
            cleaned = cleaned.translate(self.homoglyph_map)
            # 5. Chuyển thành chữ thường
            cleaned = " ".join(cleaned.lower().split())
            # 6. Teencode
            for pattern, repl in self.teencode_map.items():
                cleaned = re.sub(pattern, repl, cleaned)
            return cleaned
        except Exception as e:
            logger.error(f"Text normalization failed: {str(e)}", exc_info=True)
            return text

    def extract_obfuscation_score(self, text: str) -> float:
        """
        Tính tỷ lệ ngụy trang / chèn ký tự vô hình trong văn bản (0.0 đến 1.0).
        Loại trừ các dấu chấm, phẩy, hai chấm, gạch chéo thông thường trong chữ số,
        ngày tháng, giờ giao dịch và biến số template.
        """
        if not text:
            return 0.0
        try:
            zws_count = len(self.zws_pattern.findall(text))
            # Loại bỏ biến mẫu [NUMBER], [MONEY], [DATE], [TIME] và các định dạng số thực tế
            cleaned = re.sub(r'\[[A-Z_]+\]', '', text)
            cleaned = re.sub(r'\d+[.,:/]\d+', '', cleaned)
            # Chỉ tính ký tự phân tách chen giữa 2 chữ cái (như "c.k", "t_i_e_n", "o-t-p")
            interspersed = len(re.findall(r'(?<=[a-zA-Z\u00C0-\u1EF9])[.\-_/\\,;:*^~+~|!@#$%&?](?=[a-zA-Z\u00C0-\u1EF9])', cleaned))
            # Đếm các ký tự xáo trộn đặc trưng của spammer bot
            symbols = len(re.findall(r'[\^~*`|{}[\]<>$]', text))
            ratio = (zws_count * 5 + interspersed * 2 + symbols) / max(len(text), 1)
            return min(ratio, 1.0)
        except Exception as e:
            logger.error(f"Failed to extract obfuscation score: {str(e)}")
            return 0.0


preprocessor = TextPreprocessor()


def remove_accents(text: str) -> str:
    """Loại bỏ dấu tiếng Việt (đưa về chữ thường không dấu)."""
    if not text:
        return ""
    text = text.replace("đ", "d").replace("Đ", "d")
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    return text


def normalize_text(text: str) -> str:
    """
    Chuẩn hóa văn bản cho các quy tắc detector:
    - Loại bỏ ký tự tàng hình / zero-width space
    - Chuẩn hóa Unicode NFKC
    - Giải ngụy trang homoglyph và dấu chèn
    - Giải nén teencode giao dịch
    - Chuyển thành chữ thường
    - Bỏ dấu tiếng Việt (do từ khóa trong vi_keywords đều là không dấu)
    - Chuẩn hóa khoảng trắng
    """
    if not isinstance(text, str) or not text.strip():
        return ""
    cleaned = preprocessor.normalize(text)
    return remove_accents(cleaned)


def prepare_model_input(text: str) -> str:
    """
    Tạo biểu diễn kép (Dual-Representation) cho mô hình học máy:
    Kết hợp bản chuẩn hóa có dấu và bản không dấu để mô hình nhận diện chính xác
    cả tin nhắn có dấu, không dấu và biến thể ngụy trang.
    """
    if not text or not text.strip():
        return ""
    clean = preprocessor.normalize(text)
    no_acc = remove_accents(clean)
    return f"{clean} [NO_ACC] {no_acc}"
# File: app/detector/phobert_classifier.py
"""
Mô-đun Trích xuất Đặc trưng Ngữ cảnh Tiếng Việt PhoBERT (PhoBERT Contextual Classifier):
- Sử dụng pre-trained model: vinai/phobert-base-v2
- Trích xuất 768-dimensional Contextual Embedding cho tin nhắn SMS tiếng Việt
- Hiểu được mối quan hệ ngữ pháp giữa phủ định/cảnh báo ("tuyệt đối không chia sẻ") và hành vi tấn công
- Cầu nối triệt tiêu hoàn toàn hiện tượng "học vẹt" của mô hình TF-IDF túi từ
"""
import os
import logging
from typing import Dict, Any, List, Optional
import numpy as np

logger = logging.getLogger(__name__)

# Canonical Threat & Safe Anchor Sentences for Contextual Similarity Comparison
CANONICAL_THREAT_SEEDS = [
    "yêu cầu cung cấp mã xác thực otp để kiểm tra giao dịch",
    "đọc giúp em mã otp vừa gửi về số điện thoại của anh",
    "nhập chuỗi ký tự vừa gửi về máy để mở khóa tài khoản",
    "tài khoản của bạn đã bị khóa vui lòng bấm vào liên kết để xác minh",
    "chuyển tiền ngay vào tài khoản cơ quan điều tra để chứng minh trong sạch",
    "lệnh bắt giam và khởi tố vụ án rửa tiền yêu cầu hợp tác chuyển khoản",
    "tuyển dụng ctv việc làm online tại nhà hoa hồng 30 phần trăm chốt đơn nạp tiền",
    "chúc mừng bạn đã trúng thưởng xe máy chuyển khoản phí làm hồ sơ để nhận quà"
]

CANONICAL_SAFE_SEEDS = [
    "cảnh báo tuyệt đối không cung cấp chia sẻ mã otp cho bất kỳ ai dưới mọi hình thức",
    "ngân hàng không bao giờ yêu cầu khách hàng đọc mã otp hay bấm vào liên kết lạ",
    "quý khách đang thực hiện giao dịch chuyển tiền mã otp xác thực là lưu ý bảo mật",
    "thông báo tài khoản quý khách vừa thay đổi số dư biến động",
    "quý khách đã đăng ký thành công gói cước data 4g tốc độ cao của nhà mạng",
    "cảnh giác với các thủ đoạn giả danh công an viện kiểm sát yêu cầu chuyển tiền"
]


class PhoBERTContextualClassifier:
    def __init__(self, model_name: str = "vinai/phobert-base-v2"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.is_loaded = False
        self.threat_seed_embeddings = None
        self.safe_seed_embeddings = None
        
    def lazy_load(self) -> bool:
        """Tải mô hình PhoBERT vào bộ nhớ khi được gọi lần đầu."""
        if self.is_loaded:
            return True
        try:
            import torch
            from transformers import AutoTokenizer, AutoModel

            logger.info(f"Đang tải pre-trained PhoBERT: {self.model_name}...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModel.from_pretrained(self.model_name)
            self.model.eval()
            self.is_loaded = True
            
            # Tính toán sẵn anchor embeddings cho các hạt giống ngữ nghĩa
            self._precompute_anchor_embeddings()
            logger.info("Khởi tạo PhoBERT Contextual Classifier thành công!")
            return True
        except Exception as e:
            logger.warning(f"Không thể nạp mô hình PhoBERT ({e}). Chuyển về chế độ fallback.")
            self.is_loaded = False
            return False

    def _precompute_anchor_embeddings(self):
        """Tính toán trước vector đại diện ngữ nghĩa của các kịch bản lừa đảo vs an toàn."""
        try:
            self.threat_seed_embeddings = self.get_embeddings_batch(CANONICAL_THREAT_SEEDS)
            self.safe_seed_embeddings = self.get_embeddings_batch(CANONICAL_SAFE_SEEDS)
        except Exception as e:
            logger.warning(f"Lỗi tính toán anchor embeddings: {e}")

    def get_embedding(self, text: str) -> Optional[np.ndarray]:
        """Trích xuất vector ngữ cảnh 768 chiều cho một câu tiếng Việt."""
        if not text or not self.lazy_load():
            return None
        try:
            import torch
            inputs = self.tokenizer(
                text,
                padding=True,
                truncation=True,
                max_length=128,
                return_tensors="pt"
            )
            with torch.no_grad():
                outputs = self.model(**inputs)
                # Mean Pooling có xét Attention Mask
                attention_mask = inputs['attention_mask'].unsqueeze(-1)
                token_embeddings = outputs.last_hidden_state
                mean_pooled = torch.sum(token_embeddings * attention_mask, dim=1) / torch.clamp(attention_mask.sum(dim=1), min=1e-9)
                vec = mean_pooled[0].cpu().numpy()
                norm = np.linalg.norm(vec)
                return vec / (norm + 1e-9)
        except Exception as e:
            logger.error(f"Lỗi trích xuất PhoBERT embedding: {e}")
            return None

    def get_embeddings_batch(self, texts: List[str]) -> Optional[np.ndarray]:
        """Trích xuất embedding cho danh sách câu theo lô."""
        if not texts or not self.lazy_load():
            return None
        try:
            import torch
            inputs = self.tokenizer(
                texts,
                padding=True,
                truncation=True,
                max_length=128,
                return_tensors="pt"
            )
            with torch.no_grad():
                outputs = self.model(**inputs)
                attention_mask = inputs['attention_mask'].unsqueeze(-1)
                token_embeddings = outputs.last_hidden_state
                mean_pooled = torch.sum(token_embeddings * attention_mask, dim=1) / torch.clamp(attention_mask.sum(dim=1), min=1e-9)
                vecs = mean_pooled.cpu().numpy()
                norms = np.linalg.norm(vecs, axis=1, keepdims=True)
                return vecs / (norms + 1e-9)
        except Exception as e:
            logger.error(f"Lỗi trích xuất PhoBERT batch embeddings: {e}")
            return None

    def compute_semantic_threat_score(self, text: str) -> Dict[str, Any]:
        """
        Tính toán điểm nguy cơ ngữ nghĩa dựa trên độ tương đồng Cosine
        với các cụm ý đồ tấn công vs cụm ý đồ bảo vệ trong không gian PhoBERT 768 chiều.
        """
        result = {
            "is_phobert_available": False,
            "semantic_threat_score": 0.0,
            "threat_similarity": 0.0,
            "safe_similarity": 0.0,
            "context_explanation": "Mô hình ngữ cảnh PhoBERT chưa sẵn sàng"
        }
        
        emb = self.get_embedding(text)
        if emb is None or self.threat_seed_embeddings is None or self.safe_seed_embeddings is None:
            return result
        
        # Cosine similarity với tập đe dọa (Threat) và tập an toàn (Safe)
        sim_threat = float(np.max(np.dot(self.threat_seed_embeddings, emb)))
        sim_safe = float(np.max(np.dot(self.safe_seed_embeddings, emb)))
        
        # Điểm tương quan chuẩn hóa [-1, 1] -> [0, 100]
        # Nếu giống Safe hơn Threat, threat_score giảm sâu
        margin = sim_threat - sim_safe
        # Sigmoid scale cho margin
        threat_score = 1.0 / (1.0 + np.exp(-5.0 * margin)) * 100.0
        
        result.update({
            "is_phobert_available": True,
            "semantic_threat_score": round(threat_score, 1),
            "threat_similarity": round(sim_threat, 4),
            "safe_similarity": round(sim_safe, 4),
            "context_explanation": (
                f"PhoBERT Context: Threat Sim={sim_threat:.2f}, Safe Sim={sim_safe:.2f}"
            )
        })
        return result


phobert_detector = PhoBERTContextualClassifier()


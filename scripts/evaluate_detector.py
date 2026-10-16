import csv
import logging
from typing import List, Dict, Tuple
from sklearn.metrics import confusion_matrix, precision_score, recall_score, accuracy_score, f1_score
from sklearn.model_selection import train_test_split
import sys
import os

# Đảm bảo import được module từ app/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.detector.scorer import RiskScorer

# Cấu hình Logging để in ra console
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DetectorEvaluator:
    def __init__(self, dataset_path: str, test_size: float = 0.2, random_state: int = 42):
        self.dataset_path = dataset_path
        self.test_size = test_size
        self.random_state = random_state
        self.scorer = RiskScorer()

    def load_data(self) -> Tuple[List[str], List[int]]:
        """Tải dữ liệu từ CSV. Giả định cấu trúc: text, label (1 là scam, 0 là safe)"""
        texts = []
        labels = []
        try:
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    texts.append(row['text'])
                    labels.append(int(row['label']))
            return texts, labels
        except Exception as e:
            logger.error(f"Failed to load dataset: {str(e)}")
            return [], []

    def evaluate_subset(self, texts: List[str], true_labels: List[int], subset_name: str = "TEST SET"):
        pred_labels = []
        false_positives = []
        false_negatives = []

        logger.info(f"Đang đánh giá {len(texts)} mẫu trên tập {subset_name}...")

        for i, text in enumerate(texts):
            result = self.scorer.analyze_message(text)
            pred_label = 1 if result["is_scam"] else 0
            pred_labels.append(pred_label)

            true_label = true_labels[i]
            if true_label == 0 and pred_label == 1:
                false_positives.append((text, result))
            elif true_label == 1 and pred_label == 0:
                false_negatives.append((text, result))

        acc = accuracy_score(true_labels, pred_labels)
        precision = precision_score(true_labels, pred_labels, zero_division=0)
        recall = recall_score(true_labels, pred_labels, zero_division=0)
        f1 = f1_score(true_labels, pred_labels, zero_division=0)
        tn, fp, fn, tp = confusion_matrix(true_labels, pred_labels, labels=[0, 1]).ravel()

        self._print_report(subset_name, acc, precision, recall, f1, tn, fp, fn, tp, len(texts))
        if false_positives:
            self._analyze_errors(false_positives, f"FALSE POSITIVES ({subset_name})")
        if false_negatives:
            self._analyze_errors(false_negatives, f"FALSE NEGATIVES ({subset_name})")

        return {"acc": acc, "precision": precision, "recall": recall, "f1": f1}

    def run_evaluation(self):
        texts, true_labels = self.load_data()
        if not texts:
            return

        # Phân chia tập dữ liệu độc lập: Train Set (80%) và Hold-out Test Set (20%)
        # Áp dụng Stratified Split để giữ nguyên tỷ lệ mẫu lừa đảo / an toàn
        X_train, X_test, y_train, y_test = train_test_split(
            texts,
            true_labels,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=true_labels,
        )

        logger.info(f"Tổng số mẫu: {len(texts)} (Train: {len(X_train)}, Test độc lập: {len(X_test)})")

        # Đánh giá trên tập kiểm thử độc lập (Tránh rò rỉ dữ liệu - Data Leakage)
        print("\n" + "#" * 60)
        print("DANH GIA TREN TAP KIEM THU DOC LAP (HOLD-OUT TEST SET - 20%)")
        print("#" * 60)
        self.evaluate_subset(X_test, y_test, subset_name="HOLD-OUT TEST SET (20%)")

    def _print_report(self, subset_name, acc, precision, recall, f1, tn, fp, fn, tp, total_samples):
        lines = [
            "\n" + "=" * 55,
            f"BAO CAO HIEU NANG PHAN TICH: {subset_name}",
            f"Tong so mau danh gia: {total_samples}",
            "=" * 55,
            f"Accuracy (Do chinh xac tong the) : {acc:.4f} ({acc*100:.2f}%)",
            f"Precision (Do tin cay)           : {precision:.4f} ({precision*100:.2f}%)",
            f"Recall (Do phu bat scam)         : {recall:.4f} ({recall*100:.2f}%)",
            f"F1-Score (Trung binh dieu hoa)   : {f1:.4f} ({f1*100:.2f}%)",
            "-" * 55,
            f"True Negatives (TN - An toan chuan)  : {tn}",
            f"True Positives (TP - Bat trung Scam) : {tp}",
            f"False Positives(FP - Chan nham oan)  : {fp} (Muc tieu: 0)",
            f"False Negatives(FN - Bo lot Scam)    : {fn}",
            "=" * 55,
        ]
        for line in lines:
            print(line)

    def _analyze_errors(self, error_list, title):
        if not error_list:
            return
        print(f"\n[PHAN TICH] {title}")
        for i, (text, result) in enumerate(error_list[:3]):
            safe_text = text.encode('ascii', 'ignore').decode()[:80]
            print(f"\nMau {i+1}: {safe_text}")
            print(f"   -> Diem rui ro: {result['risk_score']}")
            safe_reason = str(result['reason']).encode('ascii', 'ignore').decode()[:100]
            print(f"   -> Ly do kich hoat: {safe_reason}")


if __name__ == "__main__":
    dataset = "data/labeled_messages.csv"
    evaluator = DetectorEvaluator(dataset, test_size=0.2, random_state=42)
    evaluator.run_evaluation()
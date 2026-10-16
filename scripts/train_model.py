# File: scripts/train_model.py
import csv
import joblib
import os
import sys
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.ensemble import VotingClassifier
from lightgbm import LGBMClassifier
from sklearn.pipeline import Pipeline, FeatureUnion

# Thiết lập đường dẫn để gọi các module tiền xử lý
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.detector.text_utils import prepare_model_input

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def train_and_save_model():
    data_path = 'data/labeled_messages.csv'
    model_save_path = 'app/detector/ml_model.joblib'

    logger.info("1. Đang tải và tiền xử lý dữ liệu với Dual-Representation (Có dấu & Không dấu)...")
    texts = []
    labels = []

    try:
        with open(data_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Biểu diễn kép: kết hợp bản có dấu và bản không dấu để mô hình học cả 2 dạng
                model_input = prepare_model_input(str(row['text']))
                texts.append(model_input)
                labels.append(int(row['label']))
    except Exception as e:
        logger.error(f"Lỗi khi đọc file CSV: {e}")
        return

    logger.info("2. Đang xây dựng Thuật toán Đa tầng Đặc trưng (FeatureUnion: Word N-grams + Char_wb N-grams)...")
    # Tầng 1: Word n-grams (1-3) bắt cụm từ ngữ nghĩa
    # Tầng 2: Character n-grams (3-5) với word boundary bắt sub-words, từ chèn ký tự, viết tắt
    features = FeatureUnion([
        ('word', TfidfVectorizer(ngram_range=(1, 3), max_features=12000, sublinear_tf=True)),
        ('char', TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), max_features=18000, sublinear_tf=True))
    ])

    logger.info("3. Cấu hình Hệ thống Ensemble Voting: LightGBM (Cây quyết định tăng cường) + Logistic Regression + Complement Naive Bayes...")
    lgbm = LGBMClassifier(
        n_estimators=200,
        learning_rate=0.06,
        num_leaves=45,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight='balanced',
        random_state=42,
        verbose=-1,
        n_jobs=-1
    )
    lr = LogisticRegression(class_weight='balanced', C=3.0, max_iter=1000, random_state=42)
    nb = ComplementNB(alpha=0.5)

    ensemble = VotingClassifier(
        estimators=[
            ('lgbm', lgbm),
            ('lr', lr),
            ('nb', nb)
        ],
        voting='soft',
        weights=[1, 2, 1]
    )

    pipeline = Pipeline([
        ('features', features),
        ('classifier', ensemble)
    ])

    logger.info(f"Đang huấn luyện mô hình Ensemble trên {len(texts)} mẫu dữ liệu...")
    pipeline.fit(texts, labels)

    logger.info("4. Đang lưu mô hình Ensemble xuống ổ cứng...")
    joblib.dump(pipeline, model_save_path)
    logger.info(f"Hoàn tất! Mô hình Ensemble LightGBM đã được lưu tại: {model_save_path}")


if __name__ == "__main__":
    train_and_save_model()
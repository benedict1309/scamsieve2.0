# File: scripts/train_phobert_classifier.py
"""
Huấn luyện Mô hình Phân loại Ngữ cảnh Tiếng Việt PhoBERT (vinai/phobert-base-v2):
- Trích xuất Contextual Embeddings 768 chiều từ PhoBERT
- Tách biệt ngữ cảnh an toàn vs lừa đảo, hiểu phạm vi phủ định
- Phân chia 70% Train - 30% Test có Stratified Sampling
- Lưu mô hình Classification Head tại app/detector/phobert_head.joblib
"""
import os
import sys
import csv
import joblib

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

DATA_PATH = 'data/labeled_messages.csv'
MODEL_SAVE_PATH = 'app/detector/phobert_head.joblib'
PHOBERT_MODEL_NAME = 'vinai/phobert-base-v2'


def train_phobert_classifier(sample_limit: int = 1200):
    print("=" * 65)
    print("BAT DAU TRIEN KHAI HUAN LUYEN PHO-BERT (CONTEXTUAL EMBEDDINGS 768-D)")
    print("=" * 65)
    
    # 1. Đọc dữ liệu
    texts = []
    labels = []
    with open(DATA_PATH, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = str(row.get('text', '')).strip()
            l = int(row.get('label', 0))
            if t:
                texts.append(t)
                labels.append(l)
                
    total_samples = len(texts)
    print(f"Tổng số mẫu trong labeled_messages.csv: {total_samples}")
    
    # Để tối ưu hóa thời gian chạy CPU trên Windows, lấy một tập mẫu cân bằng đại diện
    if sample_limit and total_samples > sample_limit:
        idx_0 = [i for i, y in enumerate(labels) if y == 0]
        idx_1 = [i for i, y in enumerate(labels) if y == 1]
        np.random.seed(42)
        sel_0 = np.random.choice(idx_0, size=min(sample_limit // 2, len(idx_0)), replace=False)
        sel_1 = np.random.choice(idx_1, size=min(sample_limit // 2, len(idx_1)), replace=False)
        selected_idx = np.concatenate([sel_0, sel_1])
        np.random.shuffle(selected_idx)
        texts = [texts[i] for i in selected_idx]
        labels = [labels[i] for i in selected_idx]
        print(f"Lấy tập mẫu đại diện cân bằng: {len(texts)} mẫu (Safe: {labels.count(0)}, Scam: {labels.count(1)})")

    # 2. Tải PhoBERT
    print(f"Đang tải pre-trained Transformer: {PHOBERT_MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(PHOBERT_MODEL_NAME)
    model = AutoModel.from_pretrained(PHOBERT_MODEL_NAME)
    model.eval()

    # 3. Trích xuất Embeddings theo lô
    print("Đang trích xuất 768-dim Contextual Embeddings...")
    batch_size = 32
    all_embeddings = []
    
    for i in range(0, len(texts), batch_size):
        batch_texts = texts[i:i + batch_size]
        inputs = tokenizer(
            batch_texts,
            padding=True,
            truncation=True,
            max_length=128,
            return_tensors="pt"
        )
        with torch.no_grad():
            outputs = model(**inputs)
            attention_mask = inputs['attention_mask'].unsqueeze(-1)
            token_embeddings = outputs.last_hidden_state
            mean_pooled = torch.sum(token_embeddings * attention_mask, dim=1) / torch.clamp(attention_mask.sum(dim=1), min=1e-9)
            norm = torch.norm(mean_pooled, p=2, dim=1, keepdim=True)
            norm_pooled = mean_pooled / (norm + 1e-9)
            all_embeddings.append(norm_pooled.cpu().numpy())
            
        if (i // batch_size) % 5 == 0:
            print(f"  -> Đã xử lý {min(i + batch_size, len(texts))}/{len(texts)} mẫu...")

    X = np.vstack(all_embeddings)
    y = np.array(labels)
    
    # 4. Phân chia 70% Train - 30% Test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    print(f"\nPhân chia dữ liệu: Train 70% ({len(X_train)} mẫu) - Test 30% ({len(X_test)} mẫu)")

    # 5. Huấn luyện Linear Classifier Head
    clf = LogisticRegression(C=2.0, max_iter=500, class_weight='balanced', random_state=42)
    clf.fit(X_train, y_train)

    # 6. Đánh giá trên tập Test
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 65)
    print("KET QUA DANH GIA MO HINH PHO-BERT TREN TAP TEST (30%):")
    print("=" * 65)
    print(f"- Accuracy  (Độ chính xác tổng thể):  {acc * 100:.2f}%")
    print(f"- Precision (Độ chuẩn xác Lừa đảo):  {prec * 100:.2f}%")
    print(f"- Recall    (Độ bao phủ Lừa đảo):    {rec * 100:.2f}%")
    print(f"- F1-Score:                          {f1 * 100:.2f}%")
    print("-" * 65)
    print(f"Ma trận nhầm lẫn (Confusion Matrix):\n")
    print(f"              Dự đoán An toàn | Dự đoán Lừa đảo")
    print(f"Thực tế An toàn:   {cm[0][0]:<10} | {cm[0][1]:<10}")
    print(f"Thực tế Lừa đảo:   {cm[1][0]:<10} | {cm[1][1]:<10}")
    print("-" * 65)
    print("\nBáo cáo phân loại chi tiết (Classification Report):")
    print(classification_report(y_test, y_pred, target_names=["An toàn", "Lừa đảo"], digits=4))

    # Lưu Classifier Head
    bundle = {
        "classifier": clf,
        "model_name": PHOBERT_MODEL_NAME,
        "metrics": {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}
    }
    joblib.dump(bundle, MODEL_SAVE_PATH)
    print(f"Da luu PhoBERT Classification Head tai: {MODEL_SAVE_PATH}")
    print("=" * 65)


if __name__ == '__main__':
    train_phobert_classifier(sample_limit=1000)


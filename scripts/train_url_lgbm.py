# File: scripts/train_url_lgbm.py
"""
Huấn luyện mô hình Phishing URL Chuẩn Công nghiệp (LightGBM):
- Sử dụng 20 đặc trưng Lexical thuần túy (không phụ thuộc crawl).
- Huấn luyện trên tập dữ liệu đa dạng quy mô công nghiệp (data/url_dataset_industrial.csv).
- Phân chia 70% Train - 30% Test có Stratified Sampling.
"""
import os
import sys
import joblib

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from lightgbm import LGBMClassifier

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.detector.url_ml_classifier import extract_20_lexical_features, LEXICAL_FEATURE_NAMES

def train_and_evaluate_industrial():
    data_path = 'data/url_dataset_industrial.csv'
    model_save_path = 'app/detector/url_lgbm_model.joblib'
    
    print("=" * 65)
    print("HUAN LUYEN MO HINH PHISHING URL CHUAN CONG NGHIEP (20 PURE LEXICAL FEATURES)")
    print("=" * 65)
    
    df = pd.read_csv(data_path)
    print(f"Tổng số bản ghi tập dữ liệu: {len(df)}")
    print(f"Phân bố nhãn:\n{df['type'].value_counts()}\n")
    
    X = []
    y = []
    
    for idx, row in df.iterrows():
        url = str(row.get('url', '')).strip()
        feats = extract_20_lexical_features(url)
        X.append(feats)
        label = 1 if str(row.get('type', '')).lower().strip() == 'phishing' else 0
        y.append(label)
        
    X = np.array(X)
    y = np.array(y)
    
    # Chia 70% Train, 30% Test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    
    print(f"Tap Train (70%): {len(X_train)} mau (Phishing: {sum(y_train)}, Benign: {len(y_train) - sum(y_train)})")
    print(f"Tap Test  (30%): {len(X_test)} mau (Phishing: {sum(y_test)}, Benign: {len(y_test) - sum(y_test)})")
    
    # Cấu hình LightGBM tối ưu chống học vẹt
    lgbm_url = LGBMClassifier(
        n_estimators=250,
        learning_rate=0.03,
        num_leaves=31,
        max_depth=5,
        min_child_samples=15,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight='balanced',
        random_state=42,
        verbose=-1
    )
    
    print("\nDang huan luyen LightGBM Classifier...")
    lgbm_url.fit(X_train, y_train)
    
    y_pred = lgbm_url.predict(X_test)
    y_prob = lgbm_url.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n" + "=" * 65)
    print("KET QUA DANH GIA MO HINH CHUAN CONG NGHIEP TREN TAP TEST (30%):")
    print("=" * 65)
    print(f"- Accuracy  (Do chinh xac tong the):  {acc * 100:.2f}%")
    print(f"- Precision (Do chuan xac Phishing): {prec * 100:.2f}%")
    print(f"- Recall    (Do bao phu Phishing):    {rec * 100:.2f}%")
    print(f"- F1-Score:                          {f1 * 100:.2f}%")
    print("-" * 65)
    print(f"Ma tran nham lan (Confusion Matrix):\n")
    print(f"              Du doan Benign  |  Du doan Phishing")
    print(f"Thuc te Benign:    {cm[0][0]:<10} |  {cm[0][1]:<10}")
    print(f"Thuc te Phishing:  {cm[1][0]:<10} |  {cm[1][1]:<10}")
    print("-" * 65)
    print("\nBao cao phan loai chi tiet (Classification Report):")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"], digits=4))
    
    # Đánh giá Feature Importance
    importances = lgbm_url.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\nTop 10 Dac trung Lexical thuan tuy quan trong nhat:")
    for rank, idx in enumerate(sorted_idx[:10], 1):
        print(f"  {rank:2d}. {LEXICAL_FEATURE_NAMES[idx]:<20} : {importances[idx]}")
        
    bundle = {
        "model": lgbm_url,
        "feature_names": LEXICAL_FEATURE_NAMES,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1
        }
    }
    joblib.dump(bundle, model_save_path)
    print(f"\nDa luu mo hinh URL LightGBM thanh cong tai: {model_save_path}")
    print("=" * 65)

if __name__ == "__main__":
    train_and_evaluate_industrial()

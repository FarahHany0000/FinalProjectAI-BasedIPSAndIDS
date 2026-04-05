"""
XGBoost Model Training Script
==============================
Trains both binary (Normal vs Attack) and multi-class (which attack type)
XGBoost models from the balanced training CSV.

Input:  data_pipeline/training_data_balanced.csv
Output: ai_models/network_xgb/binary_model.json
        ai_models/network_xgb/attack_model.json
        ai_models/network_xgb/scaler.pkl
"""
import sys
import pathlib
import json
import time
import warnings

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from collections import Counter
import joblib

warnings.filterwarnings("ignore")

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT = pathlib.Path(__file__).resolve().parent.parent  # network_module/
sys.path.insert(0, str(ROOT))
from config.settings import ATTACK_CLASSES, ATTACK_LABEL2ID, XGBOOST_PARAMS

CSV_PATH = ROOT / "data_pipeline" / "training_data_balanced.csv"
MODEL_DIR = ROOT.parent.parent.parent / "ai_models" / "network_xgb"
MODEL_DIR.mkdir(parents=True, exist_ok=True)


def _detect_device():
    """Auto-detect best XGBoost device."""
    try:
        X_test = np.random.rand(50, 5).astype(np.float32)
        y_test = np.random.randint(0, 2, 50)
        clf = xgb.XGBClassifier(
            tree_method="hist", device="cuda",
            n_estimators=2, max_depth=2, verbosity=0
        )
        clf.fit(X_test, y_test)
        print("  [GPU] CUDA available - using GPU acceleration")
        return "hist", "cuda"
    except Exception:
        print("  [CPU] Using CPU training (this is normal)")
        return "hist", "cpu"


def main():
    print("=" * 60)
    print("  XGBoost Network IDS - Training")
    print("=" * 60)

    # ── Load data ────────────────────────────────────────────────────────────
    if not CSV_PATH.exists():
        print(f"\nERROR: Training CSV not found: {CSV_PATH}")
        print("Run pcap_to_csv.py and balance_data.py first.")
        return

    df = pd.read_csv(str(CSV_PATH))
    print(f"\n  Training data: {len(df):,} samples")
    print(f"  Features: {len(df.columns) - 1}")
    print(f"\n  Class distribution:")
    for cls, cnt in df["label"].value_counts().items():
        print(f"    {cls:<15} {cnt:>6,}")

    # ── Prepare features and labels ──────────────────────────────────────────
    feature_cols = [c for c in df.columns if c != "label"]
    X = df[feature_cols].values.astype(np.float32)

    # Binary labels: Normal=0, Attack=1
    y_binary = (df["label"] != "Normal").astype(int).values

    # Attack class labels (only for attack samples)
    y_attack = df["label"].map(ATTACK_LABEL2ID).fillna(-1).astype(int).values

    # ── Scale features ───────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X).astype(np.float32)
    joblib.dump(scaler, str(MODEL_DIR / "scaler.pkl"))
    with open(str(MODEL_DIR / "feature_names.json"), "w") as f:
        json.dump(feature_cols, f)
    print(f"\n  Scaler saved to {MODEL_DIR / 'scaler.pkl'}")

    # ── Split data ───────────────────────────────────────────────────────────
    X_train, X_test, yb_train, yb_test, ya_train, ya_test = train_test_split(
        X_scaled, y_binary, y_attack,
        test_size=0.20, random_state=42, stratify=y_binary
    )
    X_train, X_val, yb_train, yb_val, ya_train, ya_val = train_test_split(
        X_train, yb_train, ya_train,
        test_size=0.15, random_state=42, stratify=yb_train
    )

    print(f"\n  Train: {len(X_train):,}  Val: {len(X_val):,}  Test: {len(X_test):,}")

    tree_method, device = _detect_device()

    # ═════════════════════════════════════════════════════════════════════════
    #  STAGE 1: Binary Model (Normal vs Attack)
    # ═════════════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 60}")
    print("  Stage 1: Binary Model (Normal vs Attack)")
    print("=" * 60)

    params_bin = XGBOOST_PARAMS.copy()
    params_bin["tree_method"] = tree_method
    params_bin["device"] = device
    params_bin["objective"] = "binary:logistic"
    params_bin["eval_metric"] = "logloss"
    early_stop = params_bin.pop("early_stopping_rounds", 20)

    binary_model = xgb.XGBClassifier(**params_bin, early_stopping_rounds=early_stop)

    t0 = time.time()
    binary_model.fit(
        X_train, yb_train,
        eval_set=[(X_train, yb_train), (X_val, yb_val)],
        verbose=50,
    )
    t_bin = time.time() - t0
    print(f"\n  Binary model trained in {t_bin:.1f}s")

    binary_model.save_model(str(MODEL_DIR / "binary_model.json"))

    # Evaluate binary model
    yb_pred = binary_model.predict(X_test)
    print(f"\n  Binary Test Results:")
    print(f"  Accuracy: {(yb_pred == yb_test).mean():.4f}")
    print(f"  Normal correctly classified: {((yb_pred == 0) & (yb_test == 0)).sum()}/{(yb_test == 0).sum()}")
    print(f"  Attack correctly classified: {((yb_pred == 1) & (yb_test == 1)).sum()}/{(yb_test == 1).sum()}")

    # ═════════════════════════════════════════════════════════════════════════
    #  STAGE 2: Attack Classifier (which attack type)
    # ═════════════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 60}")
    print("  Stage 2: Attack Classifier (5 classes)")
    print("=" * 60)

    # Only use attack samples
    atk_mask_train = yb_train == 1
    atk_mask_val = yb_val == 1

    X_atk_train = X_train[atk_mask_train]
    y_atk_train = ya_train[atk_mask_train]
    X_atk_val = X_val[atk_mask_val]
    y_atk_val = ya_val[atk_mask_val]

    # Balanced class weights
    class_counts = Counter(y_atk_train)
    total_atk = len(y_atk_train)
    n_classes = len(class_counts)
    weight_map = {c: total_atk / (n_classes * cnt) for c, cnt in class_counts.items()}
    sample_weights = np.array([weight_map[y] for y in y_atk_train], dtype=np.float32)

    print(f"\n  Attack training samples: {len(X_atk_train):,}")
    for cls_id, cls_name in enumerate(ATTACK_CLASSES):
        cnt = (y_atk_train == cls_id).sum()
        w = weight_map.get(cls_id, 0)
        print(f"    {cls_name:<15} {cnt:>5,} samples  weight={w:.2f}")

    params_atk = XGBOOST_PARAMS.copy()
    params_atk["tree_method"] = tree_method
    params_atk["device"] = device
    params_atk["objective"] = "multi:softprob"
    params_atk["num_class"] = len(ATTACK_CLASSES)
    params_atk["eval_metric"] = "mlogloss"
    early_stop_atk = params_atk.pop("early_stopping_rounds", 20)

    attack_model = xgb.XGBClassifier(**params_atk, early_stopping_rounds=early_stop_atk)

    t0 = time.time()
    attack_model.fit(
        X_atk_train, y_atk_train,
        eval_set=[(X_atk_train, y_atk_train), (X_atk_val, y_atk_val)],
        sample_weight=sample_weights,
        verbose=50,
    )
    t_atk = time.time() - t0
    print(f"\n  Attack model trained in {t_atk:.1f}s")

    attack_model.save_model(str(MODEL_DIR / "attack_model.json"))

    # ═════════════════════════════════════════════════════════════════════════
    #  EVALUATION
    # ═════════════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 60}")
    print("  Full Pipeline Evaluation (on test set)")
    print("=" * 60)

    # Stage 1: binary on test
    yb_pred_prob = binary_model.predict_proba(X_test)[:, 1]
    yb_pred = (yb_pred_prob >= 0.70).astype(int)

    # Stage 2: attack type for predicted attacks
    atk_mask_test = yb_pred == 1
    ya_pred_full = np.full(len(X_test), -1)
    if atk_mask_test.any():
        ya_pred_full[atk_mask_test] = attack_model.predict(X_test[atk_mask_test])

    # Per-class accuracy
    print(f"\n  Per-Class Results (threshold=0.70):")
    print(f"  {'Class':<15} {'Correct':>8} {'Total':>8} {'Accuracy':>10}")
    print(f"  {'-'*15} {'-'*8} {'-'*8} {'-'*10}")

    # Normal
    normal_mask = ya_test == -1
    normal_correct = ((yb_pred[normal_mask] == 0)).sum()
    normal_total = normal_mask.sum()
    print(f"  {'Normal':<15} {normal_correct:>8} {normal_total:>8} {normal_correct/max(normal_total,1)*100:>9.1f}%")

    # Attacks
    for cls_id, cls_name in enumerate(ATTACK_CLASSES):
        cls_mask = ya_test == cls_id
        cls_correct = (ya_pred_full[cls_mask] == cls_id).sum()
        cls_total = cls_mask.sum()
        pct = cls_correct / max(cls_total, 1) * 100
        status = "PASS" if pct >= 85 else "LOW"
        print(f"  {cls_name:<15} {cls_correct:>8} {cls_total:>8} {pct:>9.1f}%  [{status}]")

    # Summary
    print(f"\n  Models saved to: {MODEL_DIR}")
    print(f"  Total training time: {t_bin + t_atk:.1f}s")
    print(f"\n  Files produced:")
    print(f"    {MODEL_DIR / 'binary_model.json'}")
    print(f"    {MODEL_DIR / 'attack_model.json'}")
    print(f"    {MODEL_DIR / 'scaler.pkl'}")
    print(f"    {MODEL_DIR / 'feature_names.json'}")
    print(f"\n{'=' * 60}")
    print("  DONE - Copy these 3 files to the laptop:")
    print("    binary_model.json, attack_model.json, scaler.pkl")
    print("=" * 60)


if __name__ == "__main__":
    main()

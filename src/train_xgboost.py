from scenario_b import load_scenario_b, FEATURE_NAMES

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from xgboost import XGBClassifier

import joblib
import numpy as np


print("=" * 60)
print("SCENARIO B - XGBOOST BASELINE")
print("=" * 60)

# Load dataset
df = load_scenario_b()

X = df[FEATURE_NAMES]
y = df["label"]

# Encode class labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Stratified 80/20 split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    stratify=y_encoded,
    random_state=42
)

print(f"Total samples: {len(df)}")
print(f"Training samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")
print(f"Features: {len(FEATURE_NAMES)}")

print("\nTraining XGBoost...")

model = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.9,
    colsample_bytree=0.9,
    objective="multi:softprob",
    eval_metric="mlogloss",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Training complete.")

# Prediction
y_pred = model.predict(X_test)

# Evaluation
accuracy = accuracy_score(y_test, y_pred)

print("\n" + "=" * 60)
print("XGBOOST MODEL EVALUATION")
print("=" * 60)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Feature importance
importance = model.feature_importances_

feature_importance = sorted(
    zip(FEATURE_NAMES, importance),
    key=lambda x: x[1],
    reverse=True
)

print("\nTop 15 Features:")
for feature, score in feature_importance[:15]:
    print(f"{feature:25s} {score:.6f}")

# Save model and supporting files
joblib.dump(model, "models/scenario_b_xgb_model.pkl")
joblib.dump(FEATURE_NAMES, "models/scenario_b_xgb_feature_names.pkl")
joblib.dump(label_encoder, "models/scenario_b_xgb_label_encoder.pkl")

print("\nSaved:")
print("  models/scenario_b_xgb_model.pkl")
print("  models/scenario_b_xgb_feature_names.pkl")
print("  models/scenario_b_xgb_label_encoder.pkl")
# train_model.py

import pandas as pd
from scipy.io import arff
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib


def train():
    print("--- 🚂 Training Phishing Detection Model ---")
    print("Loading Training Dataset.arff...")

    try:
        # Load ARFF file
        data, meta = arff.loadarff('.\\models\\Training Dataset.arff')
        df = pd.DataFrame(data)

        # Decode byte strings to integers
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = df[col].str.decode('utf-8').astype(int)

        # Split Data
        X = df.drop('Result', axis=1)
        y = df['Result']

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        # Train Random Forest
        print(f"Training Model on {len(X_train)} samples...")
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)

        # Evaluate
        y_pred = clf.predict(X_test)
        print(f"Model Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")

        # Save model
        joblib.dump(clf, "models/phishing_model.pkl")
        print("✅ Model saved to models/phishing_model.pkl")

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    train()

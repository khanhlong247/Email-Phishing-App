import joblib
import numpy as np

class EmailClassifier:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)

    def predict(self, text):
        X_input = [text]
        raw_pred = self.model.predict(X_input)[0]
        if hasattr(self.model, "decision_function"):
            margin = float(self.model.decision_function(X_input)[0])
        elif hasattr(self.model, "predict_proba"):
            margin = float(np.max(self.model.predict_proba(X_input)[0]))
        else:
            margin = None

        label = "NON-SPAM" if margin < 1.0 else "SPAM"
        return label, margin

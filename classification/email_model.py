import joblib
import numpy as np
import warnings

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message="Trying to unpickle estimator")

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

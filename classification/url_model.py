import xgboost as xgb
import numpy as np
from .feature_extractor import extract_url_features
from config import PHISH_LABEL

class URLClassifier:
    def __init__(self, model_path):
        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)

    def predict(self, url):
        feats = extract_url_features(url)
        score = float(self.model.predict_proba(feats)[0][PHISH_LABEL])
        label = "PHISHING" if score < 0.1 else "LEGIT"
        return label, score

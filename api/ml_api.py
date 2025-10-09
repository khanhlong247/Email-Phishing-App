from fastapi import FastAPI, HTTPException
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import pickle
import os
import logging

app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.INFO, filename='data/logs/api.log')

# Load pre-trained model and vectorizer with error handling
try:
    model_path = os.path.join('models', 'trained_model.pkl')
    vectorizer_path = os.path.join('models', 'vectorizer.pkl')
    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        raise FileNotFoundError(f"Missing files: {model_path} or {vectorizer_path}")
    with open(model_path, 'rb') as f:
        clf = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)
    logging.info("Models loaded successfully from models/")
except FileNotFoundError as e:
    logging.error(f"Model files not found: {e}")
    raise HTTPException(status_code=500, detail="Model files not found")
except Exception as e:
    logging.error(f"Error loading models: {e}")
    raise HTTPException(status_code=500, detail="Error loading models")

@app.post("/predict")
async def predict(text: str):
    if not text:
        raise HTTPException(status_code=400, detail="Text input is required")
    try:
        features = vectorizer.transform([text])
        prob = clf.predict_proba(features)[0][1]
        label = "spam" if prob > 0.5 else "ham"
        logging.info(f"Predicted: prob={prob}, label={label} for text='{text[:50]}...'")
        return {"probability": float(prob), "label": label}
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail="Prediction failed")
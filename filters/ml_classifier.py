import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from config.settings import MODEL_PATH
import logging
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

logging.basicConfig(level=logging.INFO, filename='data/logs/ml.log')

# Load NLTK resources
nltk.download('stopwords', quiet=True)

# Load pre-trained model and vectorizer
with open(MODEL_PATH, 'rb') as f:
    clf = pickle.load(f)
with open('models/vectorizer.pkl', 'rb') as f:  # Assume vectorizer is saved separately
    vectorizer = pickle.load(f)

def preprocess_text(text: str) -> str:
    stop_words = set(stopwords.words('english'))
    stemmer = PorterStemmer()
    text = re.sub(r'\W', ' ', text.lower())
    words = text.split()
    words = [stemmer.stem(word) for word in words if word not in stop_words]
    return ' '.join(words)

def classify_with_ml(body: str) -> float:
    processed = preprocess_text(body)
    features = vectorizer.transform([processed])
    prob = clf.predict_proba(features)[0][1]  # Assuming binary classifier, prob of spam
    logging.info(f"ML classification probability: {prob}")
    return prob
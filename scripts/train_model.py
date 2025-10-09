import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
import pickle
import logging

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    train = pd.read_csv('data/train.csv')
    test = pd.read_csv('data/test.csv')

    vectorizer = TfidfVectorizer()
    X_train = vectorizer.fit_transform(train['processed'])
    y_train = train['label']

    clf = MultinomialNB()
    clf.fit(X_train, y_train)

    X_test = vectorizer.transform(test['processed'])
    y_pred = clf.predict(X_test)
    acc = accuracy_score(test['label'], y_pred)
    logging.info(f"Model accuracy: {acc}")

    with open('models/trained_model.pkl', 'wb') as f:
        pickle.dump(clf, f)
    with open('models/vectorizer.pkl', 'wb') as f:
        pickle.dump(vectorizer, f)
    logging.info("Model trained and saved.")
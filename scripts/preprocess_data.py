import os
import email
import pandas as pd
from sklearn.model_selection import train_test_split
from filters.ml_classifier import preprocess_text  # Reuse preprocess function
import logging

logging.basicConfig(level=logging.INFO)

def load_spamassassin_data(path: str = 'data/spamassassin'):
    data = []
    labels = []
    for root, dirs, files in os.walk(path):
        for file in files:
            with open(os.path.join(root, file), 'rb') as f:
                msg = email.message_from_bytes(f.read())
                body = msg.get_payload(decode=True).decode(errors='replace') if msg.get_payload() else ""
                data.append(body)
                labels.append(1 if 'spam' in root else 0)
    return pd.DataFrame({'text': data, 'label': labels})

if __name__ == "__main__":
    df = load_spamassassin_data()
    df['processed'] = df['text'].apply(preprocess_text)
    train, test = train_test_split(df, test_size=0.2)
    train.to_csv('data/train.csv', index=False)
    test.to_csv('data/test.csv', index=False)
    logging.info("Data preprocessed and split.")
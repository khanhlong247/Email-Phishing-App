import mysql.connector
from mysql.connector import Error
from datetime import datetime
from classification.feature_extractor import extract_url_features, FEATURE_ORDER
from config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
import numpy as np

class MySQLLogger:
    def __init__(self):
        self.conn = None

    def connect(self):
        self.conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        return self.conn.cursor()

    def log(self, result, from_addr):
        try:
            cursor = self.connect()

            # 1️⃣ Lưu email classification
            cursor.execute(
                "INSERT INTO email_classification (content, spam_result) VALUES (%s, %s)",
                (result.get("body", ""), result.get("email_label", "UNKNOWN"))
            )

            # 2️⃣ Lấy danh sách cột hiện có
            cursor.execute("SHOW COLUMNS FROM url_phishing_analysis")
            db_columns = [r[0] for r in cursor.fetchall()]

            # 3️⃣ Lưu từng URL
            if "url_checks" in result and result["url_checks"]:
                for url, label, score in result["url_checks"]:
                    features = extract_url_features(url).iloc[0].to_dict()
                    features["url"] = url
                    features["phishing_result"] = label
                    features["phishing_score"] = score

                    cols, vals = ["url"], [url]
                    for feat in FEATURE_ORDER:
                        if feat in db_columns:
                            val = features.get(feat, 0.0)
                            try:
                                val = float(val)
                                if np.isnan(val) or np.isinf(val): val = 0.0
                            except: val = 0.0
                            cols.append(feat)
                            vals.append(val)

                    if "phishing_result" in db_columns:
                        cols.append("phishing_result")
                        vals.append(label)
                    if "phishing_score" in db_columns:
                        cols.append("phishing_score")
                        vals.append(score)
                    if "timestamp" in db_columns:
                        cols.append("timestamp")
                        vals.append(datetime.now())

                    placeholders = ", ".join(["%s"] * len(vals))
                    query = f"INSERT INTO url_phishing_analysis ({', '.join(cols)}) VALUES ({placeholders})"
                    cursor.execute(query, tuple(vals))

            self.conn.commit()
            print(f"[OK] Saved {len(result.get('url_checks', []))} URLs from {from_addr}")
        except Error as e:
            print(f"[ERROR] MySQL logging failed: {e}")
        finally:
            if self.conn and self.conn.is_connected():
                cursor.close()
                self.conn.close()

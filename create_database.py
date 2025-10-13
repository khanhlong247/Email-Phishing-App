import os
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv

# ======================
# Load environment variables
# ======================
load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_NAME = os.getenv("DB_NAME", "security_analysis")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")


def create_database(cursor):
    """Tạo database nếu chưa tồn tại."""
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        print(f"✅ Database '{DB_NAME}' created or already exists.")
    except mysql.connector.Error as err:
        print(f"❌ Failed to create database: {err}")
        exit(1)


def create_tables(cursor):
    """Tạo các bảng cần thiết nếu chưa tồn tại."""
    # Bảng 1: Kết quả phân loại email
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_classification (
            id INT AUTO_INCREMENT PRIMARY KEY,
            content TEXT NOT NULL,
            spam_result VARCHAR(20) NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    print("✅ Table 'email_classification' created or already exists.")

    # Bảng 2: Kết quả phân tích URL / phishing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_phishing_analysis (
            id INT AUTO_INCREMENT PRIMARY KEY,
            url VARCHAR(255) NOT NULL,
            url_length FLOAT,
            hostname_length FLOAT,
            path_length FLOAT,
            nb_dots FLOAT,
            nb_hyphens FLOAT,
            nb_at FLOAT,
            nb_qm FLOAT,
            nb_and FLOAT,
            nb_or FLOAT,
            nb_eq FLOAT,
            nb_underscore FLOAT,
            nb_tilde FLOAT,
            nb_percent FLOAT,
            nb_slash FLOAT,
            nb_star FLOAT,
            nb_colon FLOAT,
            nb_comma FLOAT,
            nb_semicolumn FLOAT,
            nb_dollar FLOAT,
            nb_space FLOAT,
            nb_www FLOAT,
            nb_com FLOAT,
            nb_dslash FLOAT,
            http_in_path FLOAT,
            https_token FLOAT,
            ratio_digits_url FLOAT,
            ratio_digits_host FLOAT,
            punycode FLOAT,
            port FLOAT,
            tld_in_path FLOAT,
            tld_in_subdomain FLOAT,
            abnormal_subdomain FLOAT,
            nb_subdomains FLOAT,
            prefix_suffix FLOAT,
            random_domain FLOAT,
            shortening_service FLOAT,
            path_extension FLOAT,
            nb_redirection FLOAT,
            nb_external_redirection FLOAT,
            length_words_raw FLOAT,
            char_repeat FLOAT,
            shortest_words_raw FLOAT,
            shortest_word_host FLOAT,
            shortest_word_path FLOAT,
            longest_words_raw FLOAT,
            longest_word_host FLOAT,
            longest_word_path FLOAT,
            avg_words_raw FLOAT,
            avg_word_host FLOAT,
            avg_word_path FLOAT,
            phish_hints FLOAT,
            domain_in_brand FLOAT,
            brand_in_subdomain FLOAT,
            brand_in_path FLOAT,
            suspecious_tld FLOAT,
            statistical_report FLOAT,
            nb_hyperlinks FLOAT,
            ratio_intHyperlinks FLOAT,
            ratio_extHyperlinks FLOAT,
            ratio_nullHyperlinks FLOAT,
            nb_extCSS FLOAT,
            ratio_intRedirection FLOAT,
            ratio_extRedirection FLOAT,
            ratio_intErrors FLOAT,
            ratio_extErrors FLOAT,
            login_form FLOAT,
            external_favicon FLOAT,
            links_in_tags FLOAT,
            submit_email FLOAT,
            ratio_intMedia FLOAT,
            ratio_extMedia FLOAT,
            sfh FLOAT,
            iframe FLOAT,
            popup_window FLOAT,
            safe_anchor FLOAT,
            onmouseover FLOAT,
            right_clic FLOAT,
            empty_title FLOAT,
            domain_in_title FLOAT,
            domain_with_copyright FLOAT,
            whois_registered_domain FLOAT,
            domain_registration_length FLOAT,
            domain_age FLOAT,
            web_traffic FLOAT,
            dns_record FLOAT,
            google_index FLOAT,
            page_rank FLOAT,
            phishing_result VARCHAR(20) NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    print("✅ Table 'url_phishing_analysis' created or already exists.")


def main():
    """Hàm chính khởi tạo database và bảng."""
    conn = None
    try:
        # Kết nối MySQL (chưa chọn database)
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = conn.cursor()
        create_database(cursor)
        cursor.execute(f"USE {DB_NAME}")
        create_tables(cursor)
        conn.commit()
        print("🎉 Database and tables setup completed successfully.")
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("❌ Access denied: check username/password.")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("❌ Database does not exist.")
        else:
            print(f"❌ Error: {err}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
            print("🔒 Database connection closed.")


if __name__ == "__main__":
    main()

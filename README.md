SMTP Gateway Spam Filter
Overview
The SMTP Gateway Spam Filter is a Python-based application designed to act as a protective layer for email systems by filtering out spam emails before they reach the recipient's inbox. This project leverages SMTP protocols, multi-layered filtering (network, content, and machine learning), and Docker for deployment, offering a customizable and scalable solution for individuals or organizations managing their own email domains. By intercepting emails at the gateway level, it enhances security, reduces server load, and provides a foundation for learning and research in email processing and machine learning.

Purpose: Protect users from spam, phishing, and other email threats.
Benefits: Improves email server performance, reduces costs compared to commercial solutions, and supports continuous improvement with ML models.
Target Users: Developers, researchers, small businesses, or anyone with control over their email domain's MX records.

Project Significance
This project addresses the growing challenge of email spam by providing a proactive filtering mechanism. It:

Enhances Security: Blocks malicious emails early, reducing risks of fraud or cyberattacks.
Optimizes Performance: Offloads spam filtering from the main mail server, improving efficiency.
Offers Flexibility: Allows customization of filters and ML models to adapt to specific needs.
Supports Education: Serves as a practical example of SMTP handling, data preprocessing, and ML application.
Reduces Costs: Provides an open-source alternative to expensive commercial spam filters.

Setup Instructions
Prerequisites

Python 3.10 or higher
Docker (for containerized deployment)
Access to configure DNS MX records for your domain

Installation

Clone the repository:git clone https://github.com/your-repo/smtp-gateway.git
cd smtp-gateway

Install dependencies:pip install -r requirements.txt

Configure environment variables:
Create or edit the .env file with your settings (e.g., PROTECTED_EMAIL, MAIN_MAIL_SERVER).
Example .env content is provided in the repository.

Prepare the ML model:
Run data preprocessing: python scripts/preprocess_data.py
Train the model: python scripts/train_model.py(Ensure the SpamAssassin dataset is in data/spamassassin or adjust the path.)

Start the gateway:python main.py

Ensure port 25 is open (may require root privileges or firewall configuration).

Docker Deployment

Build the Docker image:docker build -t smtp-gateway .

Run the container:docker run -p 25:25 --env-file .env smtp-gateway

Map port 25 and provide the .env file for configuration.

DNS Configuration

Update the MX record of your domain (e.g., example.com) to point to your gateway server (e.g., mail.your-gateway-server.com).
Add an A record for the gateway server's IP.
Example:example.com MX 10 mail.your-gateway-server.com
mail.your-gateway-server.com A <Your Server IP>

Testing
Run unit tests to verify filter functionality:
python -m unittest discover tests

Note: Tests for test_smtp_handler.py are placeholders and require mock implementations for full coverage.

Project Structure and Component Meanings
Configuration (config/settings.py)

Purpose: Centralizes application settings using environment variables.
Significance: Enables flexible deployment across environments, secures sensitive data (e.g., passwords), and allows customization of spam thresholds and blacklists.

SMTP Handling (core/smtp_handler.py)

Purpose: Core logic for receiving emails, applying filters, and deciding to forward or reject.
Significance: Implements multi-layered filtering (network → content → ML), optimizes performance with early rejection, and logs for debugging.

Email Forwarding (core/forwarder.py)

Purpose: Forwards clean emails to the main mail server.
Significance: Ensures continuity of email delivery with secure TLS connections and error logging.

Network Filter (filters/network.py)

Purpose: Checks sender IP against blacklists (e.g., Spamhaus).
Significance: Provides a fast, low-cost initial filter to block known spam sources.

Content Filter (filters/content.py)

Purpose: Applies rule-based checks for spam keywords or patterns.
Significance: Detects simple spam cases, easy to update, and reduces false negatives.

ML Classifier (filters/ml_classifier.py)

Purpose: Uses a pre-trained ML model to classify emails based on content.
Significance: Enhances accuracy with TF-IDF and Naive Bayes, adaptable to evolving spam trends.

Data Preprocessing (scripts/preprocess_data.py)

Purpose: Prepares and splits training data from datasets like SpamAssassin.
Significance: Ensures high-quality input for ML training, critical for model performance.

Model Training (scripts/train_model.py)

Purpose: Trains and saves the ML model with accuracy evaluation.
Significance: Provides a reusable model, supports retraining with new data, and validates performance.

Filter Tests (tests/test_filters.py)

Purpose: Unit tests for filter components.
Significance: Verifies individual filter reliability, aids in early error detection.

SMTP Handler Tests (tests/test_smtp_handler.py)

Purpose: Tests SMTP handling logic (currently a placeholder).
Significance: Ensures gateway behavior aligns with protection rules, needs mock implementation.

Main Entry Point (main.py)

Purpose: Launches the SMTP Gateway server.
Significance: Simplifies startup, supports async processing, and provides runtime feedback.

Environment File (.env)

Purpose: Stores configuration variables.
Significance: Secures sensitive data, simplifies configuration changes, and supports multi-server deployment.

Docker Configuration (Dockerfile)

Purpose: Defines the Docker container setup.
Significance: Ensures consistent deployment, supports scaling, and reduces setup errors.

Documentation (README.md)

Purpose: Guides users on setup, testing, and deployment.
Significance: Enhances accessibility, supports community adoption, and adds professionalism.

Dependencies (requirements.txt)

Purpose: Lists required Python libraries.
Significance: Ensures dependency consistency, simplifies installation, and avoids version conflicts.

Future Improvements

Enhance ML: Integrate deep learning models (e.g., LSTM) for better accuracy.
Add Feedback Loop: Allow user reporting to retrain models dynamically.
Improve Security: Implement DKIM/SPF validation and rate limiting.
Scale: Add load balancing for high-volume email traffic.

Contributing
Feel free to fork this repository, submit issues, or pull requests. Contributions to improve filters, add features, or optimize performance are welcome!
License
[MIT License] - Free for use, modification, and distribution.

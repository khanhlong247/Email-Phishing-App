import smtplib
from email.mime.text import MIMEText

msg = MIMEText("This is a test email.")
msg['Subject'] = 'Test Email'
msg['From'] = 'sender@gmail.com'
msg['To'] = 'khanhlong024@gmail.com'

try:
    with smtplib.SMTP('localhost', 2525) as server:
        server.set_debuglevel(1)  # Enable debug output
        server.send_message(msg)
    print("Email sent to proxy server.")
except Exception as e:
    print(f"Error sending email: {str(e)}")
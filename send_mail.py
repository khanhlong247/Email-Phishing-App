import smtplib
from email.mime.text import MIMEText

msg = MIMEText("Hi, you can search whatever you want at https://www.google.com/")
msg['Subject'] = 'Email from Google'
msg['From'] = 'namtranhoang134@gmail.com'
msg['To'] = 'khanhlong024@gmail.com'

try:
    with smtplib.SMTP('192.168.1.109', 2525) as server:
        server.set_debuglevel(1)  # Enable debug output
        server.send_message(msg)
    print("Email sent to proxy server.")
except Exception as e:
    print(f"Error sending email: {str(e)}")
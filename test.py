import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(subject, body, to_email, from_email, smtp_server, smtp_port, smtp_user, smtp_password):
    # 
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    # 
    msg.attach(MIMEText(body, 'plain'))

    # 
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()  # 
    server.login(smtp_user, smtp_password)  # 

    # 
    server.sendmail(from_email, to_email, msg.as_string())

    # 
    server.quit()

# 
if __name__ == '__main__':
    subject = "Hello from Python"
    body = "This is a test email sent from a Python script using Gmail SMTP."
    to_email = "recipient@example.com"
    from_email = "your-email@gmail.com"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "email@gmail.io"
    smtp_password = "your-app-password"

    send_email(subject, body, to_email, from_email, smtp_server, smtp_port, smtp_user, smtp_password)
# utils.py
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

def send_registration_email(email: str, registration_token: str):
    sender_email = os.getenv("SMTP_EMAIL")
    receiver_email = email
    password = os.getenv("SMTP_PASSWORD")
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))

    message = MIMEMultipart("alternative")
    message["Subject"] = "ReviewO Registration"
    message["From"] = sender_email
    message["To"] = receiver_email

    text = f"Hi,\n\nClick the link below to complete your registration:\n\nhttp://localhost:8000/register?email={email}&token={registration_token}\n\nThis link is valid for one-time use."
    html = f"""\
    <html>
    <body>
        <p>Hi,<br>
        Click the link below to complete your registration:<br>
        <a href="http://localhost:8000/register?email={email}&token={registration_token}">Complete Registration</a>
        <br><br>This link is valid for one-time use.
        </p>
    </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    message.attach(part1)
    message.attach(part2)

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())

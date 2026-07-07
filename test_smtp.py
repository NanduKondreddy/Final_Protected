import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

def test_connection():
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        smtp_port = 587
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)

    print(f"Target Host: {smtp_host}")
    print(f"Target Port: {smtp_port}")
    print(f"SMTP User:   {smtp_user}")
    print(f"SMTP Pass:   {'[SET]' if smtp_password else '[NOT SET]'}")
    print(f"SMTP From:   {smtp_from}")

    if not smtp_user or not smtp_password:
        print("\n[ERROR] SMTP_USER or SMTP_PASSWORD is not set in your environment/.env file.")
        return

    try:
        print("\n1. Connecting to server...")
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        
        print("2. Starting TLS...")
        server.starttls()
        
        print("3. Logging in...")
        server.login(smtp_user, smtp_password)
        
        print("4. Sending test email...")
        msg = MIMEText("This is a test email from ShieldIQ to verify SMTP configuration.")
        msg["Subject"] = "ShieldIQ SMTP Connection Test"
        msg["From"] = smtp_from
        msg["To"] = smtp_user
        
        server.sendmail(smtp_from, [smtp_user], msg.as_string())
        server.quit()
        print("\n[SUCCESS] Test email sent successfully to " + smtp_user)
    except Exception as e:
        print(f"\n[FAILURE] SMTP Error details:\n{e}")

if __name__ == "__main__":
    test_connection()

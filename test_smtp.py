import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys

def send_test_email():
    sender = "security-alert@paypal-update-center.xyz"
    recipient = "victim@target-enterprise.com"
    
    msg = MIMEMultipart()
    msg['From'] = "PayPal Security Support <security-alert@paypal-update-center.xyz>"
    msg['To'] = recipient
    # Include an authentic-looking authentication header block to simulate email routing headers
    msg['Authentication-Results'] = "spf=fail (sender IP is 198.51.100.42) smtp.mailfrom=paypal-update-center.xyz"
    msg['Subject'] = "URGENT: Your PayPal account has been restricted - Action Needed"
    
    body = """Dear customer,
We detected suspicious activity on your PayPal account. To secure your account and restore access, please click the link below to verify your identity.

Verify Identity: http://login-paypal.com.account-update.xyz/login.php

If you do not verify your account within 24 hours, it will be suspended.
"""
    msg.attach(MIMEText(body, 'plain'))
    
    print("Connecting to SMTP Receiver Middleware on localhost:2525...")
    try:
        server = smtplib.SMTP('localhost', 2525)
        server.sendmail(sender, [recipient], msg.as_string())
        server.quit()
        print("Success! Test email sent successfully to the SMTP middleware.")
    except Exception as e:
        print("Error: Failed to connect or send via SMTP port 2525.", file=sys.stderr)
        print(e, file=sys.stderr)

if __name__ == '__main__':
    send_test_email()

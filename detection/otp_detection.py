# otp_detection.py

import re

# Function to detect OTP patterns in the message
def detect_otp(message):
    otp_pattern = r"\b\d{6}\b"  # Matches 6-digit OTPs
    return re.findall(otp_pattern, message)

# Two-Factor Authentication (2FA) with Python

## Overview
This project implements a Two-Factor Authentication (2FA) system using Time-based One-Time Passwords (TOTP). It generates a secret key and allows users to verify their identity with a one-time password. Additionally, it creates a QR code that can be scanned by authenticator apps like Google Authenticator.

## Features
- **Secret Key Generation**: Generates a unique base32 secret key.
- **OTP Generation**: Generates time-based one-time passwords.
- **OTP Verification**: Allows users to verify the OTP they enter.
- **QR Code Generation**: Creates a QR code for easy scanning with authenticator apps.

## Requirements
- Python 3.x
- `pyotp` library
- `qrcode` library

## Installation
1. **Install Python 3**: Ensure you have Python 3 installed on your system.
2. **Install Required Libraries**:
   ```bash
   sudo apt install python3-pip
   pip3 install pyotp qrcode[pil]

Usage
Clone the Repository (if applicable):
bash
git clone <repository-url>
cd <repository-directory>

Run the Script:
Save the following code in a file named Hamidou2FA.py:
python
import pyotp
import qrcode
import time

# Step 1: Generate a secret key
key = pyotp.random_base32()  # You can also manually assign a key
print(f"Secret Key: {key}")

# Step 2: Create a TOTP object based on the secret key
totp = pyotp.TOTP(key)

# Step 3: Generate the QR Code for scanning with Google Authenticator
uri = totp.provisioning_uri(name="user@example.com", issuer_name="MyApp")
qrcode_img = qrcode.make(uri)
qrcode_img.save("totp_qr.png")
print("QR Code generated and saved as 'totp_qr.png'.")

# Step 4: Generate the current OTP (Time-based One-Time Password)
print(f"Current OTP: {totp.now()}")

# Step 5: Verify the OTP code entered by the user
user_code = input("Enter the 2FA code: ")
if totp.verify(user_code):
    print("Code is valid")
else:
    print("Code is invalid")

# Step 6: Demonstrate OTP expiration by waiting 30 seconds
print("Waiting 30 seconds for OTP expiration...")
time.sleep(30)

new_code = totp.now()
print(f"New OTP after 30 seconds: {new_code}")

Scan the QR Code:
After running the script, locate the generated QR code image (totp_qr.png) in your project directory. Use an authenticator app to scan this QR code.
Enter OTP:
The script will display the current OTP. Enter this OTP in the terminal when prompted.
Notes
The OTP is valid for only 30 seconds. After that, a new OTP will be generated.
Ensure that you keep your secret key secure, as it is essential for generating valid OTPs.
License
This project is licensed under the MIT License.
text

Feel free to modify any sections as needed!

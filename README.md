# Secure File Storage

## Overview

The Secure File Storage project provides a robust solution for securely encrypting and decrypting files using AES (Advanced Encryption Standard) with a 256-bit key. Developed as part of the MATH319 course at Qassim university, this application uses Python and Streamlit to offer a user-friendly interface for managing file security.

## Features

- **User Interface**: Intuitive design for easy file upload and password entry.
- **User Authentication**: Password-based key derivation for AES encryption.
- **File Upload**: Supports a variety of file types, including `.txt`, `.pdf`, `.jpg`, `.png`, and `.csv`.
- **AES Encryption**: Utilizes AES-256 encryption to ensure strong data protection.
- **Decryption**: Securely decrypts files with the correct password.

## How It Works

### Encryption

1. Users upload a file and enter a password.
2. The application generates a random salt and initialization vector (IV).
3. A key is derived from the password using the Scrypt key derivation function (KDF).
4. The file is padded, encrypted using AES in CBC mode, and saved along with the salt and IV.

### Decryption

1. Users upload an encrypted file and provide the password used for encryption.
2. The application extracts the salt and IV from the file.
3. The key is derived using the same password and salt.
4. The file is decrypted, unpadded, and saved.

## Contributors

- **Yazeed Asim Alramadi**
- **Salman Saleh Alkhalifah**
- **Mohammed Ali Aldubayyan**
- **Abdulrrahman Abdullah Alowaymir**
- **Salman Mohammed Alayed**

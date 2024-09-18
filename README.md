# -Secure-File-Storage

Overview
The Secure File Storage project is designed to securely encrypt and decrypt files using AES (Advanced Encryption Standard) with a 256-bit key. This project was developed for the MATH319 course at [Your College] and provides an easy-to-use interface for file encryption and decryption. The application is built using Python and Streamlit, leveraging the cryptography library for secure AES-256 encryption and decryption.

Features
User Interface: A simple and intuitive interface for file upload and password input.
User Authentication: Uses passwords to derive AES encryption keys.
File Upload: Supports various file types including .txt, .pdf, .jpg, .png, and .csv.
AES Encryption: Implements AES-256 encryption to ensure data security.
Retrieval and Decryption: Allows users to decrypt files securely with the correct password.
How It Works
Encryption:

Users upload a file and provide a password.
The application generates a random salt and initialization vector (IV).
A key is derived from the password using the Scrypt key derivation function (KDF).
The file is padded, encrypted using AES in CBC mode, and saved with the salt and IV.
Decryption:

Users upload an encrypted file and provide the password used for encryption.
The application extracts the salt and IV from the encrypted file.
The key is derived using the same password and salt.
The file is decrypted, unpadded, and saved.
Contributors
Yazeed Asim Alramadi
Salman Saleh Alkhalifah
Mohammed Ali Aldubayyan
Abdulrrahman Alowaymir
Salman Mohammed Alayed
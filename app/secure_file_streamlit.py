import os
import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

class AESFileEncryptionApp:
    def __init__(self):
        self.iv_size = 16  # Initialization vector size for AES is 16 bytes
        self.block_size = 128  # Block size for AES (in bits)

    def derive_key(self, password: str, salt: bytes):
        """Derive a 32-byte AES key from the password and salt."""
        kdf = Scrypt(
            salt=salt,
            length=32,  # AES-256 requires a 32-byte key
            n=2**14, r=8, p=1,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key

    def encrypt_file(self, file, password: str):
        """Encrypt the uploaded file using AES."""
        salt = os.urandom(16)  # Generate a random salt
        key = self.derive_key(password, salt)  # Derive key using password and salt
        
        iv = os.urandom(self.iv_size)  # Generate a random IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        original = file.read()

        # Add padding to align with AES block size
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(original) + padder.finalize()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_file_path = f"encrypted_{file.name}"
        with open(encrypted_file_path, 'wb') as encrypted_file:
            # Save salt, IV, and encrypted data in one file
            encrypted_file.write(salt + iv + encrypted_data)

        return encrypted_file_path

    def decrypt_file(self, file, password: str):
        """Decrypt the uploaded file using AES."""
        encrypted = file.read()

        salt = encrypted[:16]  # Extract the first 16 bytes for salt
        iv = encrypted[16:16 + self.iv_size]  # Next 16 bytes for IV
        encrypted_data = encrypted[16 + self.iv_size:]  # The rest is the encrypted data

        key = self.derive_key(password, salt)  # Derive key using password and salt
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding from decrypted data
        unpadder = padding.PKCS7(self.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        decrypted_file_path = f"decrypted_{file.name}"
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        return decrypted_file_path

def main():
    # change font to Cabin
    st.markdown("""
        <style>
            body {
                font-family: 'Cabin', sans-serif;
                background-color: #f4f4f4;
                color: #333;
            }
            .title {
                text-align: center;
                color: #4A90E2;
                font-size: 2.5em;
                margin-bottom: 20px;
            }
            .subheader {
                color: #333;
                margin-top: 20px;
            }
            .error-message {
                color: #e74c3c; /* Red color for error messages */
                font-weight: bold;
                margin-top: 10px;
            }
            .contributor {
                background-color: #ffffff;
                padding: 10px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                margin-bottom: 20px;
            }
            .horizontal-line {
                margin: 40px 0;
                border: 1px solid #e0e0e0;
            }
        </style>
        """, unsafe_allow_html=True)

    st.markdown('<div class="title">MATH319 - Secure File Storage Project (AES)</div>', unsafe_allow_html=True)
    st.markdown(""" 
        AES (Advanced Encryption Standard) is a secure symmetric key encryption method that encrypts data in 128-bit blocks using key sizes of 128, 192, or 256 bits, making it widely used for protecting sensitive information.
    """)

    app = AESFileEncryptionApp()

    # User selects the operation to perform
    operation = st.selectbox("Choose Operation", ["Encrypt File", "Decrypt File"])

    if operation == "Encrypt File":
        st.subheader("Encrypt File")
        password = st.text_input("Enter a password for encryption", type="password")
        uploaded_file = st.file_uploader("Choose a file to encrypt", type=["txt", "pdf", "jpg", "png", "csv"])

        if uploaded_file is not None and password:
            encrypted_file_path = app.encrypt_file(uploaded_file, password)
            st.success(f"File encrypted successfully: {encrypted_file_path}")
            with open(encrypted_file_path, "rb") as f:
                st.download_button(
                    label="Download Encrypted File",
                    data=f,
                    file_name=encrypted_file_path
                )

    elif operation == "Decrypt File":
        st.subheader("Decrypt File")
        password = st.text_input("Enter the password used for encryption", type="password")
        uploaded_file = st.file_uploader("Choose a file to decrypt", type=["txt", "pdf", "jpg", "png", "csv"])

        error_message = ""
        if uploaded_file is not None and password:
            try:
                decrypted_file_path = app.decrypt_file(uploaded_file, password)
                st.success(f"File decrypted successfully: {decrypted_file_path}")
                with open(decrypted_file_path, "rb") as f:
                    st.download_button(
                        label="Download Decrypted File",
                        data=f,
                        file_name=decrypted_file_path
                    )
            except Exception:
                error_message = "Incorrect password or file format. Please check and try again."

        if error_message:
            st.error(error_message, icon="🚫")

    # Contributor section
    st.markdown("<div class='horizontal-line'></div>", unsafe_allow_html=True)
    st.subheader("Contributors")
    st.write("""
    - Yazeed Asim Alramadi
    - Salman Saleh Alkhalifah
    - Mohammed Ali Aldubayyan
    - Abdulrrahman Abdullah Alowaymir
    - Salman Mohammed Alayed
    """)

if __name__ == "__main__":
    main()

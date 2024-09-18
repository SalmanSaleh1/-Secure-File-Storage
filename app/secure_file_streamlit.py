import os
import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

class AESFileEncryptionApp:
    def __init__(self):
        self.key_file = 'aes_key.key'
        self.iv_size = 16  # Initialization vector size for AES is 16 bytes
        self.block_size = 128  # Block size for AES (in bits)

    def generate_key(self, password: str):
        """Generate a 32-byte AES key from a password using Scrypt."""
        salt = os.urandom(16)  # Generate a random salt
        kdf = Scrypt(
            salt=salt,
            length=32,  # AES-256 requires a 32-byte key
            n=2**14, r=8, p=1,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())  # Derive a key from the password
        with open(self.key_file, 'wb') as key_file:
            key_file.write(salt + key)  # Save the salt and key together
        return f"Key generated and saved as {self.key_file}"

    def load_key(self, password: str):
        """Load the AES key from the key file using the password."""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as key_file:
                salt = key_file.read(16)  # First 16 bytes are the salt
                key = key_file.read(32)  # Next 32 bytes are the AES key
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2**14, r=8, p=1,
                    backend=default_backend()
                )
                return kdf.derive(password.encode())
        return None

    def encrypt_file(self, file, password: str):
        """Encrypt the uploaded file using AES."""
    # Generate key only if it doesn't exist
        if not os.path.exists(self.key_file):
            self.generate_key(password)

        key = self.load_key(password)
        if key is None:
            return "Key file not found or wrong password."

    # Encryption logic continues here...


        # Create an AES cipher object with the key and a random IV
        iv = os.urandom(self.iv_size)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Read the content of the file
        original = file.read()

        # Add padding to the file content
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(original) + padder.finalize()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_file_path = f"encrypted_{file.name}"
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(iv + encrypted_data)  # Prepend IV to the encrypted content

        return encrypted_file_path

    def decrypt_file(self, file, password: str):
        """Decrypt the uploaded file using AES."""
        key = self.load_key(password)
        if key is None:
            return "Key file not found. Please generate a key first."

        # Read the encrypted content from the file
        encrypted = file.read()
        iv = encrypted[:self.iv_size]  # Extract the IV from the start of the file
        encrypted_data = encrypted[self.iv_size:]  # The rest is the encrypted data

        # Create an AES cipher object with the key and the IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding from the decrypted data
        unpadder = padding.PKCS7(self.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        decrypted_file_path = f"decrypted_{file.name}"
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        return decrypted_file_path

def main():
    # Title and introduction for the Streamlit app
    st.title("🔒 Secure File - Encrypt & Decrypt Files (AES-256)")
    st.markdown("""
    Welcome to the AES Secure File application! Use this app to encrypt and decrypt files securely.
    Make sure to generate an encryption key before encrypting or decrypting files.
    """)

    app = AESFileEncryptionApp()

    # User selects the operation to perform
    operation = st.selectbox("Choose Operation", ["Generate Key", "Encrypt File", "Decrypt File"])

    if operation == "Generate Key":
        st.subheader("Generate AES Encryption Key")
        password = st.text_input("Enter a password for key generation", type="password")
        if st.button("Generate Key"):
            if password:
                result = app.generate_key(password)
                st.success(result)
                st.write("**Note:** Keep the key file safe. It is required for decryption.")
            else:
                st.error("Please enter a password to generate the key.")

    elif operation == "Encrypt File":
        st.subheader("Encrypt File")
        password = st.text_input("Enter the password used to generate the key", type="password")
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
        password = st.text_input("Enter the password used to generate the key", type="password")
        uploaded_file = st.file_uploader("Choose a file to decrypt", type=["txt", "pdf", "jpg", "png", "csv"])

        if uploaded_file is not None and password:
            decrypted_file_path = app.decrypt_file(uploaded_file, password)
            if "decrypted_" in decrypted_file_path:
                st.success(f"File decrypted successfully: {decrypted_file_path}")
                with open(decrypted_file_path, "rb") as f:
                    st.download_button(
                        label="Download Decrypted File",
                        data=f,
                        file_name=decrypted_file_path
                    )
            else:
                st.error(decrypted_file_path)

if __name__ == "__main__":
    main()

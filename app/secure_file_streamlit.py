import streamlit as st
from cryptography.fernet import Fernet
import os

class SecureFileApp:
    def __init__(self):
        # File path for storing the encryption key
        self.key_file = 'secret.key'

    def generate_key(self):
        """Generate a new encryption key and save it to a file."""
        # Generate a key using Fernet
        key = Fernet.generate_key()
        # Save the generated key to a file
        with open(self.key_file, 'wb') as key_file:
            key_file.write(key)
        return f"Key generated and saved as {self.key_file}"

    def load_key(self):
        """Load the encryption key from the key file."""
        # Check if the key file exists before trying to read it
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as key_file:
                return key_file.read()
        return None

    def encrypt_file(self, file):
        """Encrypt the uploaded file using the loaded encryption key."""
        # Load the encryption key
        key = self.load_key()
        if key is None:
            return "Key file not found. Please generate a key first."
        
        # Create a Fernet cipher object with the key
        fernet = Fernet(key)
        # Read the content of the file
        original = file.read()
        # Encrypt the content
        encrypted = fernet.encrypt(original)
        # Define path for the encrypted file
        encrypted_file_path = f"encrypted_{file.name}"
        
        # Save the encrypted content to a new file
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
        
        return encrypted_file_path

    def decrypt_file(self, file):
        """Decrypt the uploaded file using the loaded encryption key."""
        # Load the encryption key
        key = self.load_key()
        if key is None:
            return "Key file not found. Please generate a key first."
        
        # Create a Fernet cipher object with the key
        fernet = Fernet(key)
        # Read the encrypted content from the file
        encrypted = file.read()
        
        try:
            # Decrypt the content
            decrypted = fernet.decrypt(encrypted)
            # Define path for the decrypted file
            decrypted_file_path = f"decrypted_{file.name}"
            
            # Save the decrypted content to a new file
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted)
            
            return decrypted_file_path
        except Exception as e:
            # Return error message if decryption fails
            return f"Decryption failed: {str(e)}"

def main():
    # Title and introduction for the Streamlit app
    st.title("🔒 Secure File - Encrypt & Decrypt Files")
    st.markdown("""
    Welcome to the Secure File application! Use this app to encrypt and decrypt files securely.
    Make sure to generate an encryption key before encrypting or decrypting files.
    """)

    app = SecureFileApp()

    # User selects the operation to perform
    operation = st.selectbox("Choose Operation", ["Generate Key", "Encrypt File", "Decrypt File"])

    if operation == "Generate Key":
        st.subheader("Generate Encryption Key")
        if st.button("Generate Key"):
            # Generate and save a new encryption key
            result = app.generate_key()
            st.success(result)
            st.write("**Note:** Keep the key file safe. It is required for decryption.")

    elif operation == "Encrypt File":
        st.subheader("Encrypt File")
        st.write("Upload the file you want to encrypt. Make sure you have already generated an encryption key.")
        uploaded_file = st.file_uploader("Choose a file to encrypt", type=["txt", "pdf", "jpg", "png", "csv"])
        
        if uploaded_file is not None:
            # Encrypt the uploaded file
            encrypted_file_path = app.encrypt_file(uploaded_file)
            st.success(f"File encrypted successfully: {encrypted_file_path}")
            
            # Provide a download button for the encrypted file
            with open(encrypted_file_path, "rb") as f:
                st.download_button(
                    label="Download Encrypted File",
                    data=f,
                    file_name=encrypted_file_path
                )

    elif operation == "Decrypt File":
        st.subheader("Decrypt File")
        st.write("Upload the file you want to decrypt. Ensure you have the correct encryption key.")
        uploaded_file = st.file_uploader("Choose a file to decrypt", type=["txt", "pdf", "jpg", "png", "csv"])
        
        if uploaded_file is not None:
            # Decrypt the uploaded file
            decrypted_file_path = app.decrypt_file(uploaded_file)
            if "decrypted_" in decrypted_file_path:
                st.success(f"File decrypted successfully: {decrypted_file_path}")
                
                # Provide a download button for the decrypted file
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

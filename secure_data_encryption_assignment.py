import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Encryption key (will be regenerated after app closes)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
stored_data = {}  # Store encrypted data and hashed passkey here
failed_attempts = 0  # Block after 3 incorrect passkey attempts

# Method to securely hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt the data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt the data if the passkey is correct
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed:
            failed_attempts = 0  # Reset attempts on correct passkey
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1  # Increment on incorrect passkey
    return None

st.set_page_config(page_title="Secure App", page_icon="🔐")

st.title("SECURE DATA ENCRYPTION SYSTEM ")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Here you can securely store and retrieve your data.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_text = st.text_area("Enter your data:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_text and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_text)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data has been securely saved!")
            st.code(encrypted, language='text')  # Display encrypted text
        else:
            st.error("⚠️ Both fields are required.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Paste the encrypted text:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("🔓 Decrypted Data:")
                st.write(result)
            else:
                st.error(f"❌ Incorrect passkey! Remaining attempts: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔐 3 incorrect attempts! Redirecting to login page...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")
elif choice == "Login":
    st.subheader("🔑 Login Page")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Access granted. Please try again.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password.")

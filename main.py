import streamlit as st # type: ignore
import hashlib
import os
import time
import json
from cryptography.fernet import Fernet # type: ignore
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "secure_data.json"
SALT = b"secure_salt"
LOCKOUT_DURATION = 60  # seconds

# Session state initialization
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0


# Load data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}


# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


# Generate key from passkey
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)


# Hash password for user login
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()


# Encrypt text using Fernet
def encrypt_text(text, passkey):
    cipher = Fernet(generate_key(passkey))
    return cipher.encrypt(text.encode()).decode()


# Decrypt text using Fernet
def decrypt_text(encrypted_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None


# Load stored data
stored_data = load_data()

# UI
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# HOME
if choice == "Home":
    st.subheader("Welcome to the Secure Data Encryption System")
    st.markdown(
        """
        This app allows you to:
        - 📝 Register and login
        - 🔐 Store encrypted data securely
        - 🔍 Retrieve and decrypt your data
        """
    )

# REGISTER
elif choice == "Register":
    st.subheader("Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.error("🚫 Username already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("⚠️ Please fill in all fields.")

# LOGIN
elif choice == "Login":
    st.subheader("Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. {remaining} attempt(s) left.")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts. Locked out for 60 seconds.")
                st.stop()

# STORE DATA
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.error("⚠️ Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("⚠️ Please fill in all fields.")

# RETRIEVE DATA
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.error("⚠️ Please login first.")
    else:
        st.subheader("🔍 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No encrypted data found.")
        else:
            st.write("📂 Encrypted Data Entries:")
            for i, item in enumerate(user_data, start=1):
                st.code(f"Entry {i}:\n{item}")

        encrypted_input = st.text_area("Enter Encrypted Text to Decrypt")
        passkey_input = st.text_input("Enter Passkey to Decrypt", type="password")

        if st.button("Decrypt"):
            result = decrypt_text(encrypted_input, passkey_input)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                st.error("❌ Incorrect passkey or corrupted data.")

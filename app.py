import os
import json
import hashlib
import streamlit as st
from cryptography.fernet import Fernet
from streamlit_cookies_manager import EncryptedCookieManager

# Page config must be first Streamlit call
st.set_page_config(page_title="🔒 Secure Data App", layout="centered")

# --- Configure Secrets and Cookies ---
# Load Fernet key from environment or Streamlit secrets
def get_fernet_cipher():
    fernet_key = os.getenv("FERNET_KEY") or st.secrets.get("FERNET_KEY")
    if not fernet_key:
        st.error("Missing FERNET_KEY. Set it in your environment or in Streamlit Cloud secrets.")
        st.stop()
    return Fernet(fernet_key.encode())

cipher = get_fernet_cipher()

# Initialize encrypted cookie manager
cookies = EncryptedCookieManager(
    prefix="my-secure-app/",
    password=os.getenv("COOKIES_PASSWORD") or st.secrets.get("COOKIES_PASSWORD")
)
if not cookies.ready():
    st.stop()  # Wait until cookies are loaded

# Key under which user accounts data will be stored in cookies
USERS_COOKIE_KEY = "users_data"

# Load users dict from cookies or initialize
try:
    users = json.loads(cookies.get(USERS_COOKIE_KEY) or "{}")
except json.JSONDecodeError:
    users = {}

# --- Utility Functions ---
def hash_string(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(token: str) -> str:
    try:
        return cipher.decrypt(token.encode()).decode()
    except Exception:
        return None

# Persist users dict back to cookies
def save_users_to_cookie():
    cookies[USERS_COOKIE_KEY] = json.dumps(users)
    cookies.save()

# Authenticate existing user
def authenticate(username: str, password: str) -> bool:
    return username in users and users[username]["password_hash"] == hash_string(password)

# Register a new user
def register_user(username: str, password: str) -> bool:
    if username in users:
        return False
    users[username] = {"password_hash": hash_string(password), "data": {}}
    save_users_to_cookie()
    return True

# Save encrypted entry under user
def save_data(username: str, title: str, text: str, passkey: str) -> bool:
    if username not in users:
        return False
    hashed_passkey = hash_string(passkey)
    token = encrypt_data(text)
    users[username]["data"][title] = {"encrypted": token, "passkey_hash": hashed_passkey}
    save_users_to_cookie()
    return True

# Retrieve and decrypt
def retrieve_data(username: str, title: str, passkey: str) -> str:
    entry = users.get(username, {}).get("data", {}).get(title)
    if not entry or entry["passkey_hash"] != hash_string(passkey):
        return None
    return decrypt_data(entry["encrypted"])


# Initialize session state variables
for var in ["authenticated", "current_user", "failed_decrypt_attempts"]:
    if var not in st.session_state:
        st.session_state[var] = False if var == "authenticated" else 0 if var == "failed_decrypt_attempts" else None

if not st.session_state.authenticated:
    st.title("Login or Sign Up")
    tab1, tab2 = st.tabs(["Login", "Sign Up"])

    with tab1:
        u = st.text_input("Username", key="login_user")
        p = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login", key="btn_login"):
            if authenticate(u, p):
                st.session_state.authenticated = True
                st.session_state.current_user = u
                st.session_state.failed_decrypt_attempts = 0
                st.success("Logged in successfully!")
                st.rerun()
            else:
                st.error("Invalid credentials.")

    with tab2:
        u2 = st.text_input("Choose Username", key="signup_user")
        p2 = st.text_input("Choose Password", type="password", key="signup_pass")
        p2c = st.text_input("Confirm Password", type="password", key="signup_pass_confirm")
        if st.button("Sign Up", key="btn_signup"):
            if not u2 or not p2:
                st.error("Username and password required.")
            elif p2 != p2c:
                st.error("Passwords do not match.")
            elif register_user(u2, p2):
                st.success("Account created. Please log in.")
            else:
                st.error("Username already exists.")

else:
    # Sidebar with logout
    st.sidebar.title(f"Hello, {st.session_state.current_user}")
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.session_state.failed_decrypt_attempts = 0
        st.rerun()

    menu = st.sidebar.radio("Menu", ["Home", "Store Data", "Retrieve Data"])

    if menu == "Home":
        st.header("Welcome to Your Secure Vault")
        st.write("Use the sidebar to store or retrieve your encrypted data.")

    elif menu == "Store Data":
        st.header("Store New Entry")
        title = st.text_input("Title")
        content = st.text_area("Content")
        key = st.text_input("Passkey", type="password")
        if st.button("Save Securely", key="btn_save"):
            if save_data(st.session_state.current_user, title, content, key):
                st.success(f"'{title}' stored successfully.")
            else:
                st.error("Failed to store data.")

    else:  # Retrieve Data
        st.header("Retrieve Entry")
        user_entries = list(users.get(st.session_state.current_user, {}).get("data", {}).keys())
        if user_entries:
            sel = st.selectbox("Select Title", user_entries)
            key = st.text_input("Passkey", type="password", key="decrypt_pass")
            if st.button("Decrypt", key="btn_decrypt"):
                result = retrieve_data(st.session_state.current_user, sel, key)
                if result is not None:
                    st.success("Decrypted successfully!")
                    st.code(result)
                    st.session_state.failed_decrypt_attempts = 0
                else:
                    st.session_state.failed_decrypt_attempts += 1
                    remaining = 3 - st.session_state.failed_decrypt_attempts
                    if remaining > 0:
                        st.error(f"Invalid passkey. Attempts remaining: {remaining}")
                    else:
                        st.error("Too many failed attempts. Please log in again.")
                        # force logout
                        st.session_state.authenticated = False
                        st.session_state.current_user = None
                        st.session_state.failed_decrypt_attempts = 0
                        st.rerun()
        else:
            st.info("No entries found. Add one via 'Store Data'.")

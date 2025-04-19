import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state variables if they don't exist
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if 'current_user' not in st.session_state:
    st.session_state.current_user = None

if 'users' not in st.session_state:
    # Format: {username: {password_hash: "...", data: {title: {encrypted_text, passkey}}}}
    st.session_state.users = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'key' not in st.session_state:
    # Generate a key (this should be stored securely in production)
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)

# Function to hash passwords and passkeys
def hash_string(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text):
    try:
        return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# Function to authenticate user
def authenticate(username, password):
    if username in st.session_state.users:
        stored_hash = st.session_state.users[username]['password_hash']
        if stored_hash == hash_string(password):
            return True
    return False

# Function to register new user
def register_user(username, password):
    if username in st.session_state.users:
        return False
    
    st.session_state.users[username] = {
        'password_hash': hash_string(password),
        'data': {}
    }
    return True

# Function to logout
def logout():
    st.session_state.authenticated = False
    st.session_state.current_user = None
    st.session_state.failed_attempts = 0

# Function to save encrypted data
def save_data(title, text, passkey):
    username = st.session_state.current_user
    hashed_passkey = hash_string(passkey)
    encrypted_text = encrypt_data(text)
    
    if username in st.session_state.users:
        st.session_state.users[username]['data'][title] = {
            'encrypted_text': encrypted_text,
            'passkey': hashed_passkey
        }
        return True
    return False

# Function to verify passkey and decrypt data
def retrieve_data(title, passkey):
    username = st.session_state.current_user
    
    if username in st.session_state.users and title in st.session_state.users[username]['data']:
        data_item = st.session_state.users[username]['data'][title]
        if data_item['passkey'] == hash_string(passkey):
            return decrypt_data(data_item['encrypted_text'])
    return None

# Main application UI
st.title("🔒 Secure Data Encryption System")

# Authentication flow
if not st.session_state.authenticated:
    st.header("Welcome to the Secure Data System")
    
    # Tab for login/signup
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login"):
            if authenticate(login_username, login_password):
                st.session_state.authenticated = True
                st.session_state.current_user = login_username
                st.session_state.failed_attempts = 0
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid username or password")
    
    with tab2:
        st.subheader("Create New Account")
        new_username = st.text_input("Choose Username", key="new_username")
        new_password = st.text_input("Choose Password", type="password", key="new_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
        
        if st.button("Sign Up"):
            if not new_username or not new_password:
                st.error("⚠️ Username and password are required")
            elif new_password != confirm_password:
                st.error("⚠️ Passwords do not match")
            elif register_user(new_username, new_password):
                st.success("✅ Account created successfully! Please login.")
                st.session_state.authenticated = True
                st.session_state.current_user = new_username
                st.rerun()
            else:
                st.error("⚠️ Username already exists")

else:
    # Main application after authentication
    st.sidebar.write(f"Logged in as: **{st.session_state.current_user}**")
    if st.sidebar.button("Logout"):
        logout()
        st.rerun()
    
    # Navigation menu
    menu = ["Home", "Store Data", "Retrieve Data"]
    choice = st.sidebar.selectbox("Navigation", menu)
    
    # Count user's stored data
    if st.session_state.current_user in st.session_state.users:
        data_count = len(st.session_state.users[st.session_state.current_user]['data'])
        st.sidebar.write(f"Your stored items: **{data_count}**")
    
    if choice == "Home":
        st.subheader("🏠 Welcome to the Secure Data System")
        st.write(f"Hello **{st.session_state.current_user}**! Use this app to **securely store and retrieve sensitive data** using unique passkeys.")
        st.write("Your data is encrypted and can only be accessed with the correct passkey.")
        
        # Display quick tips
        st.info("💡 Quick Tips:")
        st.markdown("""
        - Use unique and memorable titles for your data entries
        - Create strong passkeys for important data
        - Your data is accessible only to you and protected by encryption
        """)
        
    elif choice == "Store Data":
        st.subheader("📂 Store Data Securely")
        
        data_title = st.text_input("Data Title (for easy retrieval later):")
        user_data = st.text_area("Enter Data:", height=200)
        passkey = st.text_input("Enter Passkey:", type="password")
        
        if st.button("Encrypt & Save"):
            if not data_title:
                st.error("⚠️ Please provide a title for your data")
            elif not user_data or not passkey:
                st.error("⚠️ Data and passkey are required")
            else:
                if save_data(data_title, user_data, passkey):
                    st.success(f"✅ Data '{data_title}' stored securely!")
                else:
                    st.error("❌ Failed to save data")
    
    elif choice == "Retrieve Data":
        st.subheader("🔍 Retrieve Your Data")
        
        # Display failed attempts warning if applicable
        if st.session_state.failed_attempts > 0:
            st.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}/3")
        
        # If user has data, show dropdown to select title
        if st.session_state.current_user in st.session_state.users:
            user_data_titles = list(st.session_state.users[st.session_state.current_user]['data'].keys())
            
            if user_data_titles:
                selected_title = st.selectbox("Select Data to Retrieve:", user_data_titles)
                passkey = st.text_input("Enter Passkey:", type="password")
                
                if st.button("Decrypt"):
                    if passkey:
                        decrypted_data = retrieve_data(selected_title, passkey)
                        
                        if decrypted_data:
                            st.success("✅ Data decrypted successfully!")
                            st.text_area("Decrypted Data:", value=decrypted_data, height=200, disabled=True)
                            st.session_state.failed_attempts = 0
                        else:
                            st.session_state.failed_attempts += 1
                            remaining = 3 - st.session_state.failed_attempts
                            st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                            
                            if st.session_state.failed_attempts >= 3:
                                st.warning("🔒 Too many failed attempts! You'll be logged out.")
                                logout()
                                st.rerun()
                    else:
                        st.error("⚠️ Passkey is required")
            else:
                st.info("You have no stored data. Go to 'Store Data' to add some!")
        else:
            st.error("User data not found. Please log out and log back in.")
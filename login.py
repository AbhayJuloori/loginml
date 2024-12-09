import streamlit as st
from pymongo import MongoClient
import bcrypt

client = MongoClient(st.secrets['MONGO_URL'])
db = client["auth_db"]
users_collection = db["users"]

def register_user(username, email, password):
    """Register a new user."""
    if users_collection.find_one({"username": username}):
        return "Username already exists."
    if users_collection.find_one({"email": email}):
        return "Email already exists."
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({"username": username, "email": email, "password": hashed_password})
    return "Registration successful!"

def authenticate_user(username, password):
    """Authenticate an existing user."""
    user = users_collection.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        return True
    return False

# Streamlit App
st.title("Authentication System with MongoDB")

menu = st.sidebar.selectbox("Menu", ["Login", "Register"])

if menu == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if authenticate_user(username, password):
            st.success("Login successful!")
            # Redirect to external link
            st.markdown(
                """<meta http-equiv="refresh" content="0; url=https://www.example.com/">""",
                unsafe_allow_html=True,
            )
        else:
            st.error("Invalid username or password")

elif menu == "Register":
    st.subheader("Register")
    username = st.text_input("Username")
    email = st.text_input("Email ID")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username and email and password:
            message = register_user(username, email, password)
            if message == "Registration successful!":
                st.success(message)
            else:
                st.error(message)
        else:
            st.error("Please fill out all fields.")

# Display MongoDB status
if st.sidebar.checkbox("Show MongoDB Connection Status"):
    try:
        client.server_info()  # Trigger a connection test
        st.sidebar.success("Connected to MongoDB!")
    except Exception as e:
        st.sidebar.error(f"Connection failed: {e}")

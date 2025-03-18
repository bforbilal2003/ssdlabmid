import sqlite3
import bcrypt
import os
import re

# Load admin credentials from environment variables
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
conn.commit()

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password):  # At least one uppercase letter
        return False
    if not re.search("[a-z]", password):  # At least one lowercase letter
        return False
    if not re.search("[0-9]", password):  # At least one digit
        return False
    if not re.search("[@#$%^&+=]", password):  # At least one special character
        return False
    return True

def register_user(username, password):
    if len(username) > 255 or len(password) > 255:
        print("Input too long!")
        return
    if not is_strong_password(password):
        print("Password is too weak! Please choose a stronger password.")
        return
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    print("User registered successfully!")

def authenticate(username, password):
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        print("Admin login successful!")
        return True
    elif user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
        print("User login successful!")
        return True
    else:
        print("Invalid credentials!")
        return False

# Main logic
print("1. Register\n2. Login")
choice = input("Enter choice: ")

if choice == "1":
    user = input("Enter username: ")
    pwd = input("Enter password: ")
    register_user(user, pwd)
elif choice == "2":
    user = input("Enter username: ")
    pwd = input("Enter password: ")
    authenticate(user, pwd)
else:
    print("Invalid choice!")

conn.close()

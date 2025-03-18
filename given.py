import sqlite3
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
conn.commit()
def authenticate(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        print("Admin login successful!")
        return True
    elif user:
        print("User login successful!")
        return True
    else:
        print("Invalid credentials!")
        return False
def register_user(username, password):
    if len(username) > 255 or len(password) > 255:
        print("Input too long!")
        return
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    print("User registered successfully!")

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

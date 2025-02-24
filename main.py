import tkinter as tk
from tkinter import messagebox
import os

USER_FILE = "database.db"

def load_users():
    users = {}
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as file:
            for line in file:
                username, password = line.strip().split(",")
                users[username] = password
    return users

def save_user(username, password):
    with open(USER_FILE, "a") as file:
        file.write(f"{username},{password}\n")

def signup():
    new_user = signup_username_entry.get()
    new_pass = signup_password_entry.get()

    users = load_users()

    if new_user in users:
        messagebox.showerror("Signup Failed", "User already exists!")
    elif new_user == "" or new_pass == "":
        messagebox.showerror("Signup Failed", "Fields cannot be empty!")
    else:
        save_user(new_user, new_pass)
        messagebox.showinfo("Signup Successful", "You can now log in!")
        signup_window.destroy()

def open_signup():
    global signup_window, signup_username_entry, signup_password_entry

    signup_window = tk.Toplevel(parent)
    signup_window.title("Sign Up")
    signup_window.geometry("350x250")  

    tk.Label(signup_window, text="New Username:", font=("Arial", 12)).pack(pady=5)
    signup_username_entry = tk.Entry(signup_window, width=30)
    signup_username_entry.pack(pady=5)

    tk.Label(signup_window, text="New Password:", font=("Arial", 12)).pack(pady=5)
    signup_password_entry = tk.Entry(signup_window, show="*", width=30)
    signup_password_entry.pack(pady=5)

    signup_button = tk.Button(signup_window, text="Sign Up", font=("Arial", 12), command=signup)
    signup_button.pack(pady=10)

def validate_login():
    userid = username_entry.get()
    password = password_entry.get()

    users = load_users()

    if userid in users and users[userid] == password:
        messagebox.showinfo("Login Successful", f"Welcome, {userid}!")
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")


parent = tk.Tk()
parent.title("Login Form")
parent.geometry("400x300")  
parent.configure(bg="#f0f0f0") 


tk.Label(parent, text="Userid:", font=("Arial", 14), bg="#f0f0f0").pack(pady=5)
username_entry = tk.Entry(parent, width=30, font=("Arial", 12))
username_entry.pack(pady=5)

tk.Label(parent, text="Password:", font=("Arial", 14), bg="#f0f0f0").pack(pady=5)
password_entry = tk.Entry(parent, show="*", width=30, font=("Arial", 12))
password_entry.pack(pady=5)

login_button = tk.Button(parent, text="Login", font=("Arial", 12), width=12, command=validate_login)
login_button.pack(pady=10)

signup_button = tk.Button(parent, text="Sign Up", font=("Arial", 12), width=12, command=open_signup)
signup_button.pack(pady=5)

parent.mainloop()
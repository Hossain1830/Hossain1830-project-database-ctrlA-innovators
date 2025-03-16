import tkinter as tk
from tkinter import messagebox
import os
import hashlib


USER_FILE = "users.txt"


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


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
        file.write(f"{username},{hash_password(password)}\n")


def signup():
    new_user = signup_username_entry.get()
    new_pass = signup_password_entry.get()
    confirm_pass = confirm_password_entry.get()


    users = load_users()


    if new_user in users:
        messagebox.showerror("Signup Failed", "User already exists!")
    elif new_user == "" or new_pass == "" or confirm_pass == "":
        messagebox.showerror("Signup Failed", "Fields cannot be empty!")
    elif new_pass != confirm_pass:
        messagebox.showerror("Signup Failed", "Passwords do not match!")
    else:
        save_user(new_user, new_pass)
        messagebox.showinfo("Signup Successful", "You can now log in!")
        signup_window.destroy()


def open_signup():
    global signup_window, signup_username_entry, signup_password_entry, confirm_password_entry


    signup_window = tk.Toplevel(parent)
    signup_window.title("Sign Up")
    signup_window.geometry("350x300")
    signup_window.configure(bg="#ffcc99")


    tk.Label(signup_window, text="New Username:", font=("Arial", 12), bg="#ffcc99").pack(pady=5)
    signup_username_entry = tk.Entry(signup_window, width=30)
    signup_username_entry.pack(pady=5)


    tk.Label(signup_window, text="New Password:", font=("Arial", 12), bg="#ffcc99").pack(pady=5)
    signup_password_entry = tk.Entry(signup_window, show="*", width=30)
    signup_password_entry.pack(pady=5)


    tk.Label(signup_window, text="Confirm Password:", font=("Arial", 12), bg="#ffcc99").pack(pady=5)
    confirm_password_entry = tk.Entry(signup_window, show="*", width=30)
    confirm_password_entry.pack(pady=5)


    signup_button = tk.Button(signup_window, text="Sign Up", font=("Arial", 12), bg="#4CAF50", fg="white", command=signup)
    signup_button.pack(pady=10)


def validate_login():
    userid = username_entry.get()
    password = password_entry.get()


    users = load_users()


    if userid in users and users[userid] == hash_password(password):
        messagebox.showinfo("Login Successful", f"Welcome, {userid}!")
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")


def forgot_password():
    def reset_password():
        username = forgot_username_entry.get()
        new_pass = new_password_entry.get()
        confirm_pass = confirm_new_password_entry.get()


        users = load_users()


        if username not in users:
            messagebox.showerror("Error", "Username does not exist!")
        elif new_pass != confirm_pass:
            messagebox.showerror("Error", "Passwords do not match!")
        else:
            users[username] = hash_password(new_pass)
            with open(USER_FILE, "w") as file:
                for user, pwd in users.items():
                    file.write(f"{user},{pwd}\n")
            messagebox.showinfo("Success", "Password reset successfully!")
            forgot_window.destroy()


    forgot_window = tk.Toplevel(parent)
    forgot_window.title("Forgot Password")
    forgot_window.geometry("350x300")
    forgot_window.configure(bg="#99ccff")


    tk.Label(forgot_window, text="Username:", font=("Arial", 12), bg="#99ccff").pack(pady=5)
    forgot_username_entry = tk.Entry(forgot_window, width=30)
    forgot_username_entry.pack(pady=5)


    tk.Label(forgot_window, text="New Password:", font=("Arial", 12), bg="#99ccff").pack(pady=5)
    new_password_entry = tk.Entry(forgot_window, show="*", width=30)
    new_password_entry.pack(pady=5)


    tk.Label(forgot_window, text="Confirm New Password:", font=("Arial", 12), bg="#99ccff").pack(pady=5)
    confirm_new_password_entry = tk.Entry(forgot_window, show="*", width=30)
    confirm_new_password_entry.pack(pady=5)


    reset_button = tk.Button(forgot_window, text="Reset Password", font=("Arial", 12), bg="#4CAF50", fg="white", command=reset_password)
    reset_button.pack(pady=10)


parent = tk.Tk()
parent.title("Login Form")
parent.geometry("400x350")
parent.configure(bg="#99ccff")


tk.Label(parent, text="Userid:", font=("Arial", 14), bg="#99ccff").pack(pady=5)
username_entry = tk.Entry(parent, width=30, font=("Arial", 12))
username_entry.pack(pady=5)


tk.Label(parent, text="Password:", font=("Arial", 14), bg="#99ccff").pack(pady=5)
password_entry = tk.Entry(parent, show="*", width=30, font=("Arial", 12))
password_entry.pack(pady=5)


login_button = tk.Button(parent, text="Login", font=("Arial", 12), width=12, bg="#4CAF50", fg="white", command=validate_login)
login_button.pack(pady=10)


signup_button = tk.Button(parent, text="Sign Up", font=("Arial", 12), width=12, bg="#ffcc99", fg="black", command=open_signup)
signup_button.pack(pady=5)


forgot_button = tk.Button(parent, text="Forgot Password", font=("Arial", 12), width=15, bg="#ff6666", fg="white", command=forgot_password)
forgot_button.pack(pady=5)


parent.mainloop()

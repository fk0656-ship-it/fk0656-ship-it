import bcrypt
import re
import os

USERS_FILE = "users.txt"

def menu():
    while True:
        print("\n--- MAIN MENU ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Try again.")


def register_user():
    print("\n--- REGISTER USER ---")
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    # Create file if not exist
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            pass

    # Check if username exists
    with open(USERS_FILE, "r") as f:
        for line in f:
            saved_user, _ = line.strip().split(":")
            if saved_user == username:
                print("Error: Username already exists.")
                input("Press enter to return to main menu")
                return

    # Save user
    with open(USERS_FILE, "a") as f:
        f.write(f"{username}:{password}\n")

    print("User registered successfully!")
    input("Press enter to return to main menu")


def login_user():
    print("\n--- LOGIN ---")
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    # If file doesn't exist → no registered users
    if not os.path.exists(USERS_FILE):
        print("No users.txt found. Please register a user first.")
        input("Press enter to return to main menu")
        return

    # Validate
    with open(USERS_FILE, "r") as f:
        for line in f:
            saved_user, saved_pass = line.strip().split(":")
            if username == saved_user and password == saved_pass:
                print("Login successful!")
                input("Press enter to return to main menu")
                return

    print("Error: Invalid username or password.")
    input("Press enter to return to main menu")
menu()






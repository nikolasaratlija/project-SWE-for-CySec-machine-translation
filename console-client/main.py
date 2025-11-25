import requests
import getpass
import os
from cryptography.fernet import Fernet

API_URL = "http://localhost:5000"  # Gateway URL


def login():
    max_attempts = 3
    attempts = 0
    while attempts < max_attempts:
        print("Welcome to the translation app")
        username = input("Username: ")
        password = getpass.getpass("Password: ")

        response = requests.post(f"{API_URL}/login", json={
            "username": username,
            "password": password
        })

        if response.status_code == 200:
            # Handle 2fa
            if response.json().get("2fa_required"):
                print("2FA required. Please enter your 6-digit code.")
                totp_code = input("TOTP code: ")
                totp_response = requests.post(f"{API_URL}/login/totp", json={"user_id": response.json()["user_id"], "totp_code": totp_code})

                if totp_response.status_code == 200:
                    token = totp_response.json()["access_token"]
                    return token
                else:
                    # print(response.json()["message"])
                    print("Login failed due to wrong totp code")
                    attempts += 1
                    continue
            else:
                token = response.json()["access_token"]
                return token
        else:
            print(response.json()["message"])
            attempts += 1
            continue
    if attempts == max_attempts:
        print("Too much attemps. Try again later")
        return None
        #TODO: implement block of user
        

def translate(token):
    text = input("Text to translate: ")
    print("\n Select target language")
    print("1. Bulgarian")
    print("2. Dutch")
    target_lang = input("Select option: ")

    if target_lang == '1':
        target_lang = 'bg'
    elif target_lang == '2':
        target_lang = 'nl'
    else:
        print("try again")

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{API_URL}/translate", json={
        "text": text,
        "target_language": target_lang
    }, headers=headers)

    if response.status_code == 200:
        print("Translation result:", response.json().get("translated_text"))
    else:
        print("Translation failed:", response.json().get("message"))

def enable_2fa(token):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{API_URL}/enable-2fa", 
                             json={},
                             headers=headers)

    # If backend returns JSON with TOTP info:
    if response.status_code == 200:
        data = response.json()
        # print("Message:", data.get("message"))
        print("Provisioning URI:", data.get("qr_uri"))

def logout(token):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(
        f"{API_URL}/logout",
        json={"reason": "user requested logout"},
        headers=headers
    )
    if response.status_code == 200:
        print(response.json().get("message"))
        return None
    else:
        print("Logout failed:", response.text)
        return token

def main_menu(token):
    while True:
        print("\n--- Main Menu ---")
        print("1. Translate text")
        print("2. Enable  2FA")
        print("3. Logout")
        choice = input("Select option: ")

        if choice == "1":
            translate(token)
        elif choice == "2":
            enable_2fa(token)
        elif choice == "3":
            token = logout(token)
            if token:
                main_menu(token)
            else:
                # After logout, new login is possible
                token = login()
                if token:
                    main_menu(token)
                break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    # key = os.environ.get("FERNET_KEY")
    # if not key:
    #     raise ValueError("FERNET_KEY not found in environment")

    # # Fernet expects bytes
    # cipher = Fernet(key.encode())

    # # Example usage
    # message = b"Hello from Docker!"
    # encrypted = cipher.encrypt(message)
    # decrypted = cipher.decrypt(encrypted)

    # print("Key:", key)
    # print("Encrypted:", encrypted.decode())
    # print("Decrypted:", decrypted.decode())
    token = login()
    if token:
        main_menu(token)
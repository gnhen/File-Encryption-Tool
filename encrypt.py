import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64


# Derives a key from the provided password and salt
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


# Encrypts the selected file
def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        plaintext_data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_file_path = file_path + ".enc"

    with open(encrypted_file_path, "wb") as ef:
        ef.write(salt + iv + ciphertext)

    messagebox.showinfo(
        "Success", f"File encrypted successfully and saved as {encrypted_file_path}"
    )


# Decrypts the selected file
def decrypt_file(encrypted_file_path, password):
    with open(encrypted_file_path, "rb") as ef:
        salt = ef.read(16)
        iv = ef.read(16)
        ciphertext = ef.read()

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    decrypted_file_path = encrypted_file_path.replace(".enc", "_decrypted")

    with open(decrypted_file_path, "wb") as df:
        df.write(plaintext)

    messagebox.showinfo(
        "Success", f"File decrypted successfully and saved as {decrypted_file_path}"
    )


# Handles file selection
def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)


# Executes encryption or decryption based on user selection
def process_file(action):
    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return

    if action == "encrypt":
        encrypt_file(file_path, password)
    elif action == "decrypt":
        decrypt_file(file_path, password)


# GUI setup
root = tk.Tk()
root.title("File Encryption Tool")
root.geometry("400x200")

# File selection
file_label = tk.Label(root, text="Select File:")
file_label.pack(pady=5)
file_entry = tk.Entry(root, width=40)
file_entry.pack(pady=5)
file_button = tk.Button(root, text="Browse", command=select_file)
file_button.pack(pady=5)

# Password entry
password_label = tk.Label(root, text="Enter Key:")
password_label.pack(pady=5)
password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(pady=5)

# Action buttons for encrypt and decrypt
encrypt_button = tk.Button(
    root, text="Encrypt", command=lambda: process_file("encrypt")
)
encrypt_button.pack(side="left", padx=10, pady=20)

decrypt_button = tk.Button(
    root, text="Decrypt", command=lambda: process_file("decrypt")
)
decrypt_button.pack(side="right", padx=10, pady=20)

# Run the GUI loop
root.mainloop()

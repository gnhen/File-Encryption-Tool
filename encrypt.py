import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


# Function to select file
def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)


# Function to select key file
def select_key_file():
    key_path = filedialog.askopenfilename()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key_path)


def encrypt_file():
    file_path = file_entry.get()
    key_path = key_entry.get()

    if not file_path or not key_path:
        messagebox.showerror("Error", "Please select both a file and a key.")
        return

    try:
        # Load the public key from the selected file
        with open(key_path, "rb") as key_file:
            try:
                public_key = serialization.load_pem_public_key(
                    key_file.read(), backend=default_backend()
                )
                print("Public key loaded successfully.")
            except Exception as e:
                raise ValueError(f"Public key loading failed: {e}")

        # Read the content of the file to be encrypted
        with open(file_path, "rb") as f:
            plaintext_data = f.read()

        if not plaintext_data:
            raise ValueError("File content is empty. Cannot encrypt empty data.")

        print(f"Read {len(plaintext_data)} bytes of file data.")

        # Generate a random symmetric key (AES)
        symmetric_key = os.urandom(32)  # AES-256
        nonce = os.urandom(12)  # Generate nonce for GCM mode

        # Encrypt the file data using AES-GCM
        cipher = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(nonce),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext_data) + encryptor.finalize()

        # Encrypt the symmetric key using RSA public key
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Print debug information during encryption
        print("Encryption debug info:")
        print(f"Nonce: {nonce.hex()[:16]}...")
        print(f"Tag: {encryptor.tag.hex()[:16]}...")
        print(f"First bytes of ciphertext: {ciphertext.hex()[:16]}...")

        # Save the encrypted content and encrypted symmetric key to a file
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as ef:
            # Write in order: encrypted symmetric key, nonce, tag, ciphertext
            ef.write(encrypted_symmetric_key)  # 256 bytes
            ef.write(nonce)  # 12 bytes
            ef.write(encryptor.tag)  # 16 bytes
            ef.write(ciphertext)

        messagebox.showinfo(
            "Success", f"File encrypted successfully. Saved as {encrypted_file_path}"
        )

    except ValueError as ve:
        messagebox.showerror("Error", f"Encryption failed: {ve}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")


def decrypt_file():
    file_path = file_entry.get()
    key_path = key_entry.get()

    if not file_path or not key_path:
        messagebox.showerror("Error", "Please select both a file and a key.")
        return

    try:
        # Load the private key from the selected file
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        # Read the encrypted content
        with open(file_path, "rb") as ef:
            # Read in order: encrypted symmetric key, nonce, tag, ciphertext
            encrypted_symmetric_key = ef.read(256)  # RSA-2048 encrypted key
            nonce = ef.read(12)  # GCM nonce
            tag = ef.read(16)  # GCM tag
            ciphertext = ef.read()  # Rest is ciphertext

        # Print detailed debugging information
        print(f"Encrypted symmetric key size: {len(encrypted_symmetric_key)}")
        print(f"Nonce size: {len(nonce)}")
        print(f"GCM tag size: {len(tag)}")
        print(f"Ciphertext size: {len(ciphertext)}")

        # Decrypt the symmetric key using RSA private key
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(f"Symmetric key decrypted. Size: {len(symmetric_key)} bytes")

        # Print first few bytes of each component for debugging
        print(f"First bytes of nonce: {nonce.hex()[:16]}...")
        print(f"First bytes of tag: {tag.hex()[:16]}...")
        print(f"First bytes of ciphertext: {ciphertext.hex()[:16]}...")

        # Decrypt the file data using AES-GCM
        cipher = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(nonce, tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        # Try decrypting in chunks to isolate where the failure might occur
        chunk_size = 8192
        plaintext_chunks = []

        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i : i + chunk_size]
            plaintext_chunks.append(decryptor.update(chunk))
            print(f"Processed chunk {i//chunk_size + 1}")

        plaintext_data = b"".join(plaintext_chunks) + decryptor.finalize()

        # Generate new filename
        # Remove '.enc' from the end
        original_path = file_path[:-4] if file_path.endswith(".enc") else file_path
        # Split the path into directory and filename
        directory = os.path.dirname(original_path)
        filename = os.path.basename(original_path)
        # Create new filename with 'dec_' prefix
        new_filename = "dec_" + filename
        # Combine directory and new filename
        decrypted_file_path = os.path.join(directory, new_filename)

        # Save the decrypted content
        with open(decrypted_file_path, "wb") as df:
            df.write(plaintext_data)

        messagebox.showinfo(
            "Success", f"File decrypted successfully. Saved as {decrypted_file_path}"
        )

    except Exception as e:
        detailed_error = f"Decryption failed: {str(e)}\nType: {type(e).__name__}"
        print(detailed_error)
        messagebox.showerror("Error", detailed_error)


# GUI setup
root = tk.Tk()
root.title("RSA File Encryption Tool")
root.geometry("500x350")

# File selection section
file_label = tk.Label(root, text="Select File:")
file_label.pack(pady=5)
file_entry = tk.Entry(root, width=50)
file_entry.pack(pady=5)
file_button = tk.Button(root, text="Browse File", command=select_file)
file_button.pack(pady=5)

# Key selection section
key_label = tk.Label(root, text="Select Key File:")
key_label.pack(pady=5)
key_entry = tk.Entry(root, width=50)
key_entry.pack(pady=5)
key_button = tk.Button(root, text="Browse Key", command=select_key_file)
key_button.pack(pady=5)

# Encrypt and Decrypt buttons
encrypt_button = tk.Button(
    root, text="Encrypt", width=20, height=2, command=encrypt_file
)
encrypt_button.pack(side="left", padx=20, pady=20)

decrypt_button = tk.Button(
    root, text="Decrypt", width=20, height=2, command=decrypt_file
)
decrypt_button.pack(side="right", padx=20, pady=20)

# Run the GUI loop
root.mainloop()

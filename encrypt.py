from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
import os
import base64


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def encrypt_file(file_path, password):
    # Generate a random salt and derive a key
    salt = os.urandom(16)
    key = derive_key(password, salt)

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    # Initialize AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read file data and pad it to fit AES block size
    with open(file_path, "rb") as f:
        plaintext_data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_data) + padder.finalize()

    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Write the salt, iv, and ciphertext to a new encrypted file
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as ef:
        ef.write(salt + iv + ciphertext)

    print(f"File encrypted successfully. Encrypted file saved as {encrypted_file_path}")


def decrypt_file(encrypted_file_path, password):
    with open(encrypted_file_path, "rb") as ef:
        # Read salt, iv, and ciphertext from the file
        salt = ef.read(16)
        iv = ef.read(16)
        ciphertext = ef.read()

    # Derive the key using the salt and the password
    key = derive_key(password, salt)

    # Initialize AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad the data
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Write the decrypted data to a new file
    decrypted_file_path = encrypted_file_path.replace(".enc", "_decrypted")
    with open(decrypted_file_path, "wb") as df:
        df.write(plaintext)

    print(f"File decrypted successfully. Decrypted file saved as {decrypted_file_path}")

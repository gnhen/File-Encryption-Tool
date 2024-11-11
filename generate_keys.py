from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_keys():
    # Generate the private key for decryption
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Derive the public key for encryption from the private key
    public_key = private_key.public_key()

    # Convert the private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Convert the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Output the keys to the CLI
    print("Encryption Key (Public Key):")
    print(public_pem.decode("utf-8"))
    print("\nDecryption Key (Private Key):")
    print(private_pem.decode("utf-8"))


# Run the function to generate and display keys
if __name__ == "__main__":
    generate_keys()

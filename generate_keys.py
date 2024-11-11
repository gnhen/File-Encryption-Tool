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

    # Save the private key (decryption key) to a file
    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save the public key (encryption key) to a file
    with open("public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("Keys generated successfully:")
    print("- 'public_key.pem' (encryption key) to share for encryption.")
    print("- 'private_key.pem' (decryption key) to keep private for decryption.")


# Run the function to generate and save keys as files
if __name__ == "__main__":
    generate_keys()

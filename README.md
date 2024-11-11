# File Encryption Tool

This tool allows you to encrypt and decrypt files using hybrid encryption (RSA + AES). It consists of two Python scripts:
```
    generate_keys.py: Used to generate public and private encryption keys.
    encrypt.py: Used to encrypt and decrypt files with the generated keys.
```
## Prerequisites

Before using the tool, you need to ensure that Python is installed on your computer, and the following Python libraries are available:
```
    cryptography: Used for cryptographic operations.
```
You can install it via pip if it's not already installed:

```pip install cryptography```

## Downloading the Tool

#### Clone the repository or download the ZIP file from GitHub.

  Clone command:
```
        git clone https://github.com/yourusername/encryption-tool.git
```
  Download ZIP: Click on the green "Code" button above the repository and select "Download ZIP".

  Place the files in a folder: Choose a folder on your computer where you can easily find it, such as:
  1. Documents/encryption_tool/
  2. Desktop/encryption_tool/

  #### This will be the working directory for the project.

  Remember the folder location: Make sure you remember the path to this folder, as you will need to access it when running the scripts.

## Setting Up

  1. Navigate to the folder where you downloaded the repository. You can do this via your file explorer or terminal.

  2. Run ```generate_keys.py``` to generate your keys:

  3. Open a terminal or command prompt.

  4. Navigate to the folder containing the scripts.

  5. Run the following command to generate your public and private keys:
```
  python generate_keys.py
```
  This will create two files:
  ```
      public_key.pem: The public key used for encrypting files.
      private_key.pem: The private key used for decrypting files.
  ```
  #### Important: Save these key files in a secure location. The public key can be shared with others, but the private key should be kept secret.

## Using the Tool
### Step 1: Encrypt a File

1. Run encrypt.py to encrypt your files.

2. Make sure you are still in the folder containing the encrypt.py, public_key.pem, and your file to be encrypted.

3. Open a terminal or command prompt and run:
```
   python encrypt.py
```
4. Select the file you wish to encrypt:
        A file explorer window will open. Navigate to and select the file you want to encrypt.

5. Select the public key ```(public_key.pem)```:
        A window will appear asking you to choose your public key file (public_key.pem) for encryption.

6. Click the Encrypt button:

    Once you have selected the file and the public key, click the "Encrypt" button.
        The tool will generate an encrypted file with the extension .enc (e.g., file_to_encrypt.txt.enc).

   ``` Note: This encrypted file is what you can securely store or share. It can only be decrypted by someone with the corresponding private key.```

### Step 2: Decrypt a File

1. Run encrypt.py again, but this time for decryption.

2. Open a terminal or command prompt and run:
```
python encrypt.py
```
3. Select the encrypted file (*.enc):

4. A file explorer window will open. Navigate to and select the encrypted file (e.g., file_to_encrypt.txt.enc).

5. Select the private key (private_key.pem):

A window will appear asking you to choose your private key file (private_key.pem) for decryption.

6. Click the Decrypt button:

7. Once you have selected the encrypted file and the private key, click the "Decrypt" button.
8. 
The tool will generate the decrypted file, and it will be saved in the same location with the same name as the original file (e.g., dec_file_to_encrypt.txt).

Troubleshooting

    If the encryption or decryption fails:
        Ensure that you are using the correct key for encryption and decryption. The public key should be used for encryption, and the private key should be used for decryption.
        Verify that you have enough disk space and that the file paths are correct.
        If you see error messages, check the details printed to the console for hints about what might be wrong.

    The file is not decrypted correctly:
        Ensure that the full ciphertext (including the RSA-encrypted symmetric key, GCM tag, and AES-encrypted file content) is properly saved and transferred. If parts are missing or corrupted, decryption will fail.

Contributing

If you find any bugs or want to contribute to this project, feel free to fork the repository and submit a pull request. Contributions are welcome!

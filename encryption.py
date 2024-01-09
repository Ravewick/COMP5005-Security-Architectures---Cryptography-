from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os

def generate_sha512_hash(file_path):
    # Generate SHA-512 hash of the file
    hasher = hashes.Hash(hashes.SHA512(), backend=default_backend())
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hasher.update(chunk)
    return hasher.finalize()

def encrypt_content(content, public_key):
    # Encrypt content with the public key
    encrypted_content = public_key.encrypt(
        content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_content

def save_to_file(data, file_path):
    # Save data to file
    with open(file_path, 'wb') as file:
        file.write(data)

def encrypt_file_and_hash(file_path, public_key, output_folder):
    # Read the file content
    with open(file_path, 'rb') as file:
        file_content = file.read()

    # Generate SHA-512 hash of the original file
    file_hash = generate_sha512_hash(file_path)

    # Save hash to a text file
    hash_file_path = os.path.join(output_folder, 'hash_value.txt')
    save_to_file(file_hash, hash_file_path)

    # Encrypt hash file content
    encrypted_hash_content = encrypt_content(file_hash, public_key)

    # Save the encrypted hash to a file
    encrypted_hash_file_path = os.path.join(output_folder, 'encrypted_hash_value.txt')
    save_to_file(encrypted_hash_content, encrypted_hash_file_path)

    # Encrypt the file content
    encrypted_content = encrypt_content(file_content, public_key)

    # Save the encrypted content to a file
    encrypted_file_path = os.path.join(output_folder, 'encrypted_sample.txt')
    save_to_file(encrypted_content, encrypted_file_path)

    print(f"File encrypted and saved to: {encrypted_file_path}")
    print(f"Hash value encrypted and saved to: {encrypted_hash_file_path}")

if __name__ == "__main__":
    # Load the public key
    public_key_path = 'C:\Crypto\Wallet\public_key.pem'
    with open(public_key_path, 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    # File to be encrypted
    file_to_encrypt = 'C:\Crypto\Health_Records\sample.txt'

    # Output folder for the encrypted files
    output_folder = 'C:\Crypto\Enc_Health_Records'

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Encrypt the file and hash value
    encrypt_file_and_hash(file_to_encrypt, public_key, output_folder)

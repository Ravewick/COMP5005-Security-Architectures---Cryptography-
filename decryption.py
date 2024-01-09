from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os

def decrypt_content(encrypted_content, private_key):
    # Decrypt content with the private key
    decrypted_content = private_key.decrypt(
        encrypted_content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_content

def save_to_file(data, file_path):
    # Save data to file
    with open(file_path, 'wb') as file:
        file.write(data)

def generate_sha512_hash(file_path):
    # Generate SHA-512 hash of the file
    hasher = hashes.Hash(hashes.SHA512(), backend=default_backend())
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hasher.update(chunk)
    return hasher.finalize()

def decrypt_and_compare(encrypted_file_path, encrypted_hash_path, private_key, output_folder):
    # Read the encrypted content from the file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_content = encrypted_file.read()

    # Read the encrypted hash value from the file
    with open(encrypted_hash_path, 'rb') as encrypted_hash_file:
        encrypted_hash_content = encrypted_hash_file.read()

    # Decrypt the file content
    decrypted_content = decrypt_content(encrypted_content, private_key)

    # Save the decrypted content to a file
    decrypted_file_path = os.path.join(output_folder, 'decrypted_sample.txt')
    save_to_file(decrypted_content, decrypted_file_path)

    print(f"File decrypted and saved to: {decrypted_file_path}")

    # Decrypt the hash value
    decrypted_hash = decrypt_content(encrypted_hash_content, private_key)

    # Generate SHA-512 hash of the decrypted file
    decrypted_file_hash = generate_sha512_hash(decrypted_file_path)

    # Compare the decrypted hash with the original hash
    if decrypted_hash == decrypted_file_hash:
        print("Hash comparison: No changes detected.")
    else:
        print("Hash comparison: Changes detected.")

if __name__ == "__main__":
    # Load the private key
    private_key_path = 'C:\Crypto\Wallet\private_key.pem'
    with open(private_key_path, 'rb') as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Encrypted file and hash paths
    encrypted_file_path = 'C:\Crypto\Enc_Health_Records\encrypted_sample.txt'
    encrypted_hash_path = 'C:\Crypto\Enc_Health_Records\encrypted_hash_value.txt'

    # Output folder for the decrypted files
    output_folder = 'C:\Crypto\Dec_Health_Records'

    # Ensure the output folder exists
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Decrypt the file and hash value and perform hash comparison
    decrypt_and_compare(encrypted_file_path, encrypted_hash_path, private_key, output_folder)

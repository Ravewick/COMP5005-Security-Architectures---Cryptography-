from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

def generate_rsa_key_pair(bits=4096, folder_path='C:\Crypto'):

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )

    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Save private key to file
    private_key_path = os.path.join(folder_path, 'private_key.pem')
    with open(private_key_path, 'wb') as private_key_file:
        private_key_file.write(private_key_pem)

    print(f"Private key saved to: {private_key_path}")

    # Get the public key
    public_key = private_key.public_key()

    # Serialize public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save public key to file
    public_key_path = os.path.join(folder_path, 'public_key.pem')
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(public_key_pem)

    print(f"Public key saved to: {public_key_path}")

if __name__ == "__main__":
    generate_rsa_key_pair()

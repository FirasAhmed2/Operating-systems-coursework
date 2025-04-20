import os
from Crypto.Cipher import DES
from base64 import b64encode, b64decode

def generate_salt():
    """Generate a random 16-bit salt."""
    return os.urandom(2)  # Generates 2 random bytes

def des_encrypt_25_times(key, plaintext):
    """Apply DES encryption 25 times."""
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = plaintext
    for _ in range(25):
        ciphertext = cipher.encrypt(ciphertext)
    return ciphertext

def encrypt_password(password):
    """Encrypt a password using the Morris-Thompson scheme."""
    # Step 1: Generate a 16-bit salt
    salt = generate_salt()
    
    # Step 2: Expand the salt to an 8-byte key
    key = (salt * 4)[:8]  # Repeat the salt to make it 8 bytes
    
    # Step 3: Pad the password to 8 bytes (DES block size)
    password_bytes = password.encode('utf-8')
    padded_password = password_bytes + b'\x00' * (8 - len(password_bytes) % 8)
    
    # Step 4: Encrypt the password 25 times
    encrypted_password = des_encrypt_25_times(key, padded_password)
    
    # Step 5: Encode the result in a readable format
    salt_encoded = b64encode(salt).decode('utf-8')  # Full base64-encoded salt (4 characters)
    encrypted_encoded = b64encode(encrypted_password).decode('utf-8')
    
    return f"{salt_encoded}{encrypted_encoded}"

def validate_password(stored_encrypted_password, input_password):
    """Validate a password against its encrypted form."""
    # Step 1: Extract the salt from the stored password
    salt_encoded = stored_encrypted_password[:4]  # First 4 characters (full base64-encoded salt)
    salt = b64decode(salt_encoded.encode('utf-8'))  # Decode back to bytes
    
    # Step 2: Expand the salt to an 8-byte key
    key = (salt * 4)[:8]
    
    # Step 3: Pad the input password to 8 bytes (DES block size)
    input_password_bytes = input_password.encode('utf-8')
    padded_input_password = input_password_bytes + b'\x00' * (8 - len(input_password_bytes) % 8)
    
    # Step 4: Encrypt the input password 25 times
    encrypted_input_password = des_encrypt_25_times(key, padded_input_password)
    
    # Step 5: Compare the result with the stored encrypted password
    encrypted_encoded = b64encode(encrypted_input_password).decode('utf-8')
    return stored_encrypted_password == f"{salt_encoded}{encrypted_encoded}"

if __name__ == "__main__":
    # List of passwords to encrypt
    passwords = ["password1", "securepass", "letmein", "admin123", "qwerty",
                 "welcome", "monkey", "sunshine", "football", "iloveyou"]
    
    # Encrypt the passwords
    encrypted_passwords = []
    for pwd in passwords:
        encrypted_pwd = encrypt_password(pwd)
        encrypted_passwords.append(encrypted_pwd)
    
    # Print the list of encrypted passwords
    print("Encrypted Passwords:")
    for ep in encrypted_passwords:
        print(ep)
    
    # Validate the passwords
    print("\nValidating Passwords:")
    for pwd, encrypted_pwd in zip(passwords, encrypted_passwords):
        if validate_password(encrypted_pwd, pwd):
            print(f"{pwd} is valid")
        else:
            print(f"{pwd} is invalid")
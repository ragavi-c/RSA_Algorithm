import random
import math
from secrets import randbelow

def is_prime(n, k=5):
    """Miller-Rabin primality test with k rounds"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
        
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
        
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=16):
    """Generate a random prime number with specified bits"""
    while True:
        num = randbelow(2**bits - 2**(bits-1)) + 2**(bits-1)
        if num % 2 != 0 and is_prime(num):
            return num

def gcd(a, b):
    """Compute greatest common divisor using Euclid's algorithm."""
    while b != 0:
        a, b = b, a % b
    return a

def modular_inverse(e, phi):
    """Find modular inverse using extended Euclidean algorithm"""
    original_phi = phi
    x1, x2 = 1, 0
    y1, y2 = 0, 1
    
    while phi != 0:
        quotient = e // phi
        e, phi = phi, e % phi
        x1, x2 = x2, x1 - quotient * x2
        y1, y2 = y2, y1 - quotient * y2
    
    if e != 1:
        raise ValueError("Modular inverse doesn't exist")
    return x1 % original_phi

def generate_keypair(p=None, q=None):
    """Generate RSA public and private key pair."""
    if p is None or q is None:
        p = generate_prime()
        q = generate_prime()
        while q == p:  # Ensure distinct primes
            q = generate_prime()
    else:
        if not (is_prime(p) and is_prime(q)):
            raise ValueError("Both numbers must be prime.")
        if p == q:
            raise ValueError("p and q cannot be equal")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    d = modular_inverse(e, phi)
    
    return ((e, n), (d, n), (p, q))

def rsa_encrypt(pk, plaintext):
    """Encrypt plaintext using RSA public key."""
    key, n = pk
    cipher = []
    for char in plaintext:
        m = ord(char)
        cipher.append(pow(m, key, n))
    return cipher

def rsa_decrypt(pk, ciphertext):
    """Decrypt ciphertext using RSA private key."""
    key, n = pk
    plain = []
    for num in ciphertext:
        plain.append(chr(pow(num, key, n)))
    return ''.join(plain)

def get_prime_input(prompt):
    """Get and validate prime number input from user."""
    while True:
        try:
            num = int(input(prompt))
            if not is_prime(num):
                print("Please enter a valid prime number.")
                continue
            return num
        except ValueError:
            print("Invalid input. Please enter an integer.")

def main():
    print("Enhanced RSA Encryption/Decryption Tool")
    print("--------------------------------------")
    
    # Choose prime generation method
    while True:
        choice = input("\nChoose an option:\n"
                      "1. Generate random primes\n"
                      "2. Enter my own primes\n"
                      "Enter choice (1/2): ").strip()
        
        if choice == '1':
            # Auto-generate primes
            public_key, private_key, primes = generate_keypair()
            p, q = primes
            print(f"\nGenerated primes: p = {p}, q = {q}")
            break
        elif choice == '2':
            # User provides primes
            p = get_prime_input("Enter first prime number: ")
            q = get_prime_input("Enter second different prime number: ")
            while p == q:
                print("Numbers must be different.")
                q = get_prime_input("Enter second different prime number: ")
            
            try:
                public_key, private_key, _ = generate_keypair(p, q)
                break
            except ValueError as e:
                print(f"Error: {e}")
        else:
            print("Invalid choice. Please enter 1 or 2.")
    
    print("\nGenerated Keys:")
    print(f"Public Key (e, n): {public_key}")
    print(f"Private Key (d, n): {private_key}")
    
    # Message encryption/decryption
    message = input("\nEnter a message to encrypt: ")
    
    # Encryption
    encrypted_msg = rsa_encrypt(public_key, message)
    print("\nEncrypted Message:", ' '.join(map(str, encrypted_msg)))
    
    # Decryption
    decrypted_msg = rsa_decrypt(private_key, encrypted_msg)
    print("Decrypted Message:", decrypted_msg)

if __name__ == '__main__':
    main()
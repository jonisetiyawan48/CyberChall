from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import gmpy2
import binascii

flag = b"MOKLET{FlagMokletJaya}"

# Generate prime numbers
p1 = getPrime(512)
p2 = gmpy2.next_prime(p1)
q1 = getPrime(512)
q2 = gmpy2.next_prime(q1)


# Compute RSA parameters
n = p1 * p2 * q1 * q2
e = 65537
phi = (p1 - 1) * (p2 - 1) * (q1 - 1) * (q2 - 1)
d = gmpy2.invert(e, phi)

# Encrypt the flag with AES
aes_key = get_random_bytes(16)  # Generate a random 128-bit AES key
cipher_aes = AES.new(aes_key, AES.MODE_CBC)  # Initialize AES cipher in CBC mode
ciphertext = cipher_aes.encrypt(pad(flag, AES.block_size))  # Encrypt the flag

# Encrypt the AES key with RSA
c_aes_key = pow(bytes_to_long(aes_key), e, n)

# Write parameters to file
with open('out1.txt', 'w') as f:
    f.write(f': \np1: {p1},\np2: {p2},\nq1: {q1},\nq2: {q2}, \nn: {n},\ne: {e},\nc_aes_key: {c_aes_key}\n')
    f.write(f'iv: {binascii.hexlify(cipher_aes.iv).decode()}\n')  # Write the AES IV
    f.write(f'ciphertext: {binascii.hexlify(ciphertext).decode()}\n')  # Write the AES-encrypted flag

import random

# Parameters for the logistic map
r = 3.99  # Control parameter for the chaotic system
x0 = random.uniform(0, 1)  # Initial condition (random value between 0 and 1)

# Function to generate chaotic keys using logistic map
def generate_chaotic_keys(length, r, x0):
    x = x0
    chaotic_keys = []
    for _ in range(length):
        x = r * x * (1 - x)  # Logistic map equation
        chaotic_value = int(x * 255)  # Convert chaotic output to an integer between 0 and 255
        while chaotic_value == 0:  # Ensure the key is non-zero
            x = r * x * (1 - x)
            chaotic_value = int(x * 255)
        chaotic_keys.append(chaotic_value)
    return chaotic_keys

# XOR encryption using generated chaotic keys
def chaotic_encrypt(shellcode, keys):
    encrypted_shellcode = bytearray()
    for i in range(len(shellcode)):
        encrypted_shellcode.append(shellcode[i] ^ keys[i])
    return encrypted_shellcode

# Example shellcode (dummy shellcode for demonstration purposes)
shellcode = bytearray([0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc8, 0x00])

# Generate chaotic keys based on shellcode length
keys = generate_chaotic_keys(len(shellcode), r, x0)

# Encrypt the shellcode
encrypted_shellcode = chaotic_encrypt(shellcode, keys)
print("Encrypted Shellcode:", encrypted_shellcode.hex())
print("Keys:", keys)

# Save the encrypted shellcode and keys to files
with open("encrypted_shellcode.bin", "wb") as f:
    f.write(encrypted_shellcode)

with open("keys.txt", "w") as f:
    f.write(",".join(map(str, keys)))
#XOR decryption (using same keys to reverse the process)
def chaotic_decrypt(encrypted_shellcode, keys):
    decrypted_shellcode = bytearray()
    for i in range(len(encrypted_shellcode)):
        decrypted_shellcode.append(encrypted_shellcode[i] ^ keys[i])
    return decrypted_shellcode

# Load the encrypted shellcode and keys
with open("encrypted_shellcode.bin", "rb") as f:
    encrypted_shellcode = bytearray(f.read())

with open("keys.txt", "r") as f:
    keys = list(map(int, f.read().strip().split(",")))

# Decrypt the shellcode
decrypted_shellcode = chaotic_decrypt(encrypted_shellcode, keys)
print("Decrypted Shellcode:", decrypted_shellcode.hex())

# Verify if the decryption matches the original shellcode
if decrypted_shellcode == bytearray([0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc8, 0x00]):  # Replace with the original shellcode
    print("Decryption successful. The decrypted shellcode matches the original.")
else:
    print("Decryption failed. The decrypted shellcode does not match the original.")
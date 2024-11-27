
# **Chaotic-Key Shellcode Toolkit**

A Python-based toolkit for generating, encrypting, and deploying shellcode using chaotic keys derived from a logistic map. This repository provides standalone utilities for encoding, decoding, and deploying encrypted shellcode, along with a comprehensive interactive CLI script for managing the entire process.

---

## **Repository Structure**

1. **`ChaosEncoder.py`**  
   A standalone script to:
   - Generate chaotic keys using a logistic map.
   - Encrypt shellcode with the generated keys.
   - Save encrypted shellcode and chaotic keys to files.

2. **`ChaosDecoder.py`**  
   A standalone script to:
   - Load encrypted shellcode and chaotic keys from files.
   - Decrypt the shellcode using the corresponding chaotic keys.
   - Verify the integrity of the decryption process.

3. **`ChaosDropper.py`**  
   A script to:
   - Generate a dropper for Linux or Windows.
   - Deploy encrypted shellcode by decrypting it in memory and executing it.

4. **`ChaosKit.py`**  
   (formerly referred to as `shellcode_tool.py`)  
   A comprehensive CLI-based script that integrates all functionality:
   - Generate Linux or Windows reverse shell payloads.
   - Encrypt and decrypt shellcode.
   - Save and load shellcode and keys.
   - Display shellcode as raw bytecode or a C-style byte array.
   - Create droppers for executing shellcode.

---

## **Features**

- **Chaotic Key Encryption**: Utilises a logistic map to generate unpredictable keys for encrypting shellcode.
- **Reverse Shell Payloads**:
  - Linux x64 TCP reverse shell.
  - Windows x64 TCP reverse shell.
- **Standalone and Integrated Scripts**:
  - Use `ChaosEncoder.py` or `ChaosDecoder.py` for standalone tasks.
  - Use `ChaosKit.py` for an interactive workflow.
- **Dropper Creation**:
  - Generate Python-based droppers for Linux or Windows.
  - Encrypted payloads are decrypted and executed in-memory.

---

## **Getting Started**

### **Prerequisites**

- Python 3.x
- Required modules (install with `pip` if not already available):
  - `mmap`
  - `ctypes`
  - `struct`
  - `socket`

### **Installation**

1. Clone the repository:
   ```bash
   git clone https://github.com/scs-labrat/chaotic-key-shellcode-tool.git
   cd chaotic-key-shellcode-tool
   ```

2. Ensure the required Python modules are installed:
   ```bash
   pip install -r requirements.txt
   ```

   *(No additional requirements are necessary unless future enhancements add dependencies.)*

---

## **Usage**

### **Standalone Scripts**

#### **1. ChaosEncoder.py**
Generate chaotic keys, encrypt shellcode, and save the results:
```bash
python ChaosEncoder.py
```
Follow prompts to:
- Provide shellcode input (e.g., hexadecimal bytes).
- Specify output filenames for encrypted shellcode and keys.

#### **2. ChaosDecoder.py**
Decrypt shellcode using corresponding chaotic keys:
```bash
python ChaosDecoder.py
```
Follow prompts to:
- Load encrypted shellcode and keys from files.
- Verify successful decryption.

#### **3. ChaosDropper.py**
Generate a platform-specific dropper:
```bash
python ChaosDropper.py
```
Follow prompts to:
- Select Linux or Windows as the target platform.
- Provide encrypted shellcode and keys.

### **Integrated Script**

#### **4. ChaosKit.py**
Run the interactive toolkit:
```bash
python ChaosKit.py
```

Follow the on-screen menu to perform tasks such as:
1. **Create Reverse Shellcode**: Generate a Linux or Windows reverse shell payload.
2. **Encrypt Shellcode**: Protect shellcode with chaotic keys.
3. **Decrypt Shellcode**: Restore encrypted payloads.
4. **Save/Load Shellcode**: Manage payloads and keys in files.
5. **Display Shellcode**: View raw bytecode or a C-style array.
6. **Create Dropper**: Generate deployment scripts for Linux or Windows.

---

## **Example Workflow**

1. **Generate Linux Reverse Shellcode**:
   ```plaintext
   Enter the target IP address for the reverse shell: 192.168.1.10
   Enter the target port number for the reverse shell: 4444
   Reverse shellcode created for IP 192.168.1.10 and port 4444.
   ```

2. **Encrypt the Payload**:
   ```plaintext
   Encrypted Shellcode: a3b2c4d5...
   Keys: [234, 122, 189, ...]
   ```

3. **Save the Payload**:
   ```plaintext
   Enter filename to save shellcode: reverse_shell.bin
   Enter filename to save keys: chaotic_keys.txt
   ```

4. **Create a Dropper**:
   ```plaintext
   Enter target platform (linux/windows): linux
   Enter filename for dropper script: dropper.py
   Dropper saved to dropper.py
   ```

---

## **Chaotic Keys**

Chaotic keys are derived from a logistic map, a mathematical function exhibiting chaotic behaviour:
```python
x = r * x * (1 - x)
```

Parameters like `r` (control parameter) and `x0` (initial condition) make the generated keys:
- Deterministic (reproducible with the same parameters).
- Highly sensitive to small changes in the parameters (unpredictable for an observer).

This unpredictability enhances obfuscation, making it harder for detection systems to identify patterns or decrypt payloads without access to the parameters.

---

## **Dropper Details**

Generated droppers are Python scripts designed to decrypt and execute shellcode in-memory. Platform-specific implementations include:

- **Linux**:
  - Memory allocation using `mmap` with executable permissions.
  - Execution using `ctypes`.

- **Windows**:
  - Memory allocation using `VirtualAlloc` with executable permissions.
  - Execution via a function pointer using `ctypes`.

---

## **Limitations**

- Currently supports **Linux x64** and **Windows x64** reverse shell payloads.
- Generated droppers require Python to run; additional steps may be needed to package them as standalone executables.

---

## **Legal Disclaimer**

This toolkit is intended for educational and authorised penetration testing purposes only. The authors are not responsible for any misuse of this tool. Always obtain proper authorisation before engaging in security testing activities.

---

## **License**

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## **Acknowledgements**

Inspired by chaotic encryption techniques and offensive security research. Special thanks to the HVCK community for fostering innovation and collaboration in cybersecurity.

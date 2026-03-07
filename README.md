## Container & Key Architecture

RV3 uses a **custom container system** for secure storage, execution, and transport of files and configurations.  
The system consists of two main components:

---

### **1. `.otc` Encrypted Container**

**Purpose:**  
- Stores folders, files, and data in a single, **encrypted container**.  
- Each file in the root container is stored in its **own subset container**, isolated from the others.  
- Access is only possible using the corresponding `.key`.

**Structure:**  
- **Header:** Contains metadata such as container version and creation timestamp.  
- **Encrypted Index:** Maps subset container paths to their locations in the main container.  
- **Subset Containers:** Each file has its own encrypted container with a **randomly generated 30-character password**.  
- **Encrypted Payload:** Contains the actual file contents inside each subset container.  

**Usage:**  
- RV3 reads the header to determine container contents before performing operations.  
- Containers can be **replaced atomically** with the `-r` flag, preventing partial overwrites.  
- Only accessible if the corresponding `.key` is available and memory requirements are met.  
- Optional `-i` flag allows RV3 to ignore RAM warnings, forcing execution in swap memory (**highly discouraged**).  
- **Performance may vary:** RV3 was run on a 20-core system with 32 GB of RAM. If the file you want to encode or decode does not fit in available RAM, the system will **slow to a halt**.

---

### **2. `.key` File**

**Purpose:**  
- Acts as the **decryption key source** for `.otc` containers.  
- Stores encryption parameters, offsets, and access information for all subset containers.

**Structure:**  
- **Encryption Parameters:** Symmetric key, IVs, and algorithm identifiers.  
- **Container Map:** Defines offsets for decrypting the main `.otc` and each subset container.  
- **Memory Requirements:** Ensures the binary only loads keys if the system has sufficient RAM (can be bypassed with `-i`).  

**Security Notes:**  
- The binary will **not load the key** if system memory is insufficient unless the `-i` flag is used.  
- Contains no plain text references to file contents; all sensitive data is encrypted.

---

### **3. Methodology / Operations**

**Container Creation:**  
1. RV3 collects files/folders into a staging area.  
2. Each file is encrypted into its own **subset container** with a **random 30-character password**.  
3. Encryption parameters for all subset containers are stored in the `.key`.  
4. The main `.otc` container is created, containing the header, index, and all subset containers.

**Container Execution / Access:**  
1. The binary loads the `.key` into memory (only if sufficient memory is available or `-i` flag is used).  
2. RV3 reads the main `.otc` header and index to locate subset containers.  
3. Decrypts each subset container as needed for execution or replacement.  
4. Optional `-r` flag replaces the original folder atomically with the `.otc` container.

**Security / Safety Features:**  
- Each file is isolated in its own **subset container**, preventing compromise of one file from affecting others.  
- Randomly generated passwords for subset containers make brute-forcing highly impractical.  
- Atomic replacement ensures folders are fully replaced or untouched.

---

### **4. Notes for Private Testers**

- Do **not share `.key` files** outside of controlled environments.  
- Always test destructive operations (`-r`) in isolated directories.  
- Using `-i` to ignore RAM warnings is **highly discouraged**, as it can force swap usage and reduce stability.  
- RV3 assumes the container is not corrupted; it does not perform integrity checks.  
- **Performance may vary:** large files or low-RAM environments may cause the system to slow significantly.  
- Future releases may optimize `.key` and `.otc` structure for macOS and additional Unix systems.

**Ghidra Opcode Extractor**
This repository contains Python (Jython) scripts for extracting opcodes from executable binaries using the Ghidra reverse engineering tool.

**Features**
- Extracts opcode mnemonics from executable sections.
- Multi-threaded extraction using Java threads for improved performance.
- Saves output to a user-defined directory.
- Designed for malware and binary analysis.

**Project Structure**
ghidra-opcode-extractor/            
-README.md                       
-.gitignore                        
scripts/                         
-opcode_extractor_multithreaded.py

**Requirements**
- [Ghidra](https://ghidra-sre.org/) (Tested on version 10.x+)
- Jython (comes with Ghidra)
- Python knowledge (for understanding the scripts)

**Usage**
### 1. In Ghidra:
- Open your project and import a binary.
- Open the 'Script Manager' from the toolbar.
- Place these scripts into your Ghidra user scripts directory (`~/ghidra_scripts/` or similar).
- Run the script on your binary.
- The extracted opcodes will be saved in `/home/kali/Downloads/Opcode/` or `/Opcode New/`.

### 2. Customization:
- You can modify the `target_sections` in the script to include/exclude specific memory sections.
- Output directory path can be changed in the script (`output_directory` variable).

**Testing**
Basic testing can be done by running the script on small known binaries and comparing the opcode output.
Advanced unit testing is limited as Ghidra scripting uses Jython and requires Ghidra's runtime environment. Utility functions can be refactored for separate testing.

**Author**
Srinija Battula  
Master’s in Cybersecurity and Threat Intelligence | Reverse Engineering Enthusiast








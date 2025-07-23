# -*- coding: utf-8 -*-
"""
Ghidra Script: Multi-threaded Opcode Extractor

This script extracts mnemonic opcodes from selected executable sections
of a binary using Java threads for performance. Intended for reverse
engineering or malware analysis purposes.

Author: Srinija Battula
"""

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import CodeUnit
from java.lang import Runnable, Thread
from java.util.concurrent import ConcurrentHashMap
import os

# Initialize API to interact with current Ghidra program
api = FlatProgramAPI(currentProgram)

# Prepare output file
input_file_name = currentProgram.getExecutablePath()
base_name = os.path.basename(input_file_name)
output_directory = "/home/kali/Downloads/Opcode_New/"
output_file_path = os.path.join(output_directory, "{}_opcode.txt".format(base_name))

print("Extracting opcodes from:", base_name)

# Target sections to extract from
target_sections = [".text", ".data", ".rdata", ".xdata", ".idata", ".rsrc", ".stub", ".reloc"]

# Thread-safe storage for opcodes from each section
section_opcodes = ConcurrentHashMap()

class OpcodeExtractor(Runnable):
    """
    Java Runnable class to extract opcodes from a given section.
    """
    def __init__(self, section):
        self.section = section

    def run(self):
        """
        Extract mnemonic opcodes from the assigned section and store in the shared map.
        """
        section_name = self.section.getName()
        startAddr = self.section.getStart()
        endAddr = self.section.getEnd()
        print("Processing section:", section_name)

        opcodes = []
        current = startAddr

        while current < endAddr:
            instr = api.getInstructionAt(current)
            if instr is None:
                api.disassemble(current)
                instr = api.getInstructionAt(current)
                if instr is None:
                    current = current.add(1)
                    continue

            mnemonic = instr.getMnemonicString()
            if mnemonic:
                opcodes.append(mnemonic)
            current = current.add(instr.getLength())

        section_opcodes.put(section_name, opcodes)
        print("Completed section:", section_name)

def extract_opcodes():
    """
    Main extraction logic: identifies relevant sections, spawns threads, writes to file.
    """
    try:
        print("Starting opcode extraction for:", base_name)

        if not os.path.exists(output_directory):
            os.makedirs(output_directory)

        open(output_file_path, "w").close()  # clear old output

        memory_blocks = api.getMemoryBlocks()
        threads = []

        # Spawn a thread for each target memory section
        for block in memory_blocks:
            if block.getName() in target_sections or block.isExecute():
                extractor = OpcodeExtractor(block)
                thread = Thread(extractor)
                threads.append(thread)
                thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Write output to file
        with open(output_file_path, "a") as output_file:
            for block in memory_blocks:
                name = block.getName()
                if name in target_sections or block.isExecute():
                    opcodes = section_opcodes.get(name, [])
                    output_file.write(f"\n# Section: {name}\n")
                    for opcode in opcodes:
                        output_file.write(f"{opcode}\n")

        print("Extraction complete. Output saved to:", output_file_path)

    except Exception as e:
        print("Error during opcode extraction:", str(e))


# Run the extraction
extract_opcodes()

# -*- coding: utf-8 -*-
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.listing import CodeUnit
from ghidra.util import Msg
import os
from java.lang import Runnable, Thread  # Import Java's Runnable and Thread classes
from java.util.concurrent import ConcurrentHashMap  # To store results safely across threads

# Initialize FlatProgramAPI for easier navigation and interaction
api = FlatProgramAPI(currentProgram)

# Define output file name based on the input file name
input_file_name = currentProgram.getExecutablePath()
base_name = os.path.basename(input_file_name)
output_directory = "/home/kali/Downloads/Opcode New/"
output_file_path = os.path.join(output_directory, "{}_opcode.txt".format(base_name))

print("Extracting OpCode")

# Define the specific sections you want to check for opcodes
target_sections = [".text", ".dacre", "_u_____", ".data", ".rdata", ".xdata", ".idata", ".stub", ".rsrc"]

# Use a thread-safe map to store opcodes in section order
section_opcodes = ConcurrentHashMap()

# Define a function to clear the code units within a given section
def clear_listing(api, start_addr, end_addr):
    """Clears the listing between the start and end addresses."""
    listing = currentProgram.getListing()
    code_units = listing.getCodeUnits(start_addr, True)
    for code_unit in code_units:
        if isinstance(code_unit, CodeUnit):
            listing.clearCodeUnits(code_unit.getMinAddress(), code_unit.getMaxAddress(), False)

# Define the extraction function that will be run in each thread
class OpcodeExtractor(Runnable):
    def __init__(self, section):
        self.section = section

    def run(self):
        """Extract opcodes from a specified section."""
        section_name = self.section.getName()
        
        # Clear code units before disassembly
        # clear_listing(api, self.section.getStart(), self.section.getEnd())
        
        startAddr = self.section.getStart()
        print("Extracting opcodes from section: {}".format(section_name))
        
        # Collect opcodes in a list for this section
        opcodes = []
        while self.section.contains(startAddr):
            instr = api.getInstructionAt(startAddr)
            if instr is None:
                api.disassemble(startAddr)
                instr = api.getInstructionAt(startAddr)
                if instr is None:
                    startAddr = startAddr.next()
                    continue
            opcode = instr.getMnemonicString()
            if opcode:
                opcodes.append(opcode)
            startAddr = startAddr.next()
        
        # Store the opcodes in the concurrent map, preserving section order
        section_opcodes.put(section_name, opcodes)

def extract_opcodes():
    """Extract opcodes from specified sections of the binary using Java threads."""
    try:
        print("Started {}".format(base_name))
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)

        # Clear the output file if it already exists
        open(output_file_path, "w").close()

        memory_blocks = api.getMemoryBlocks()
        threads = []
        print("Memory Blocks: ", memory_blocks)
        # Create and start a thread for each section
        for block in memory_blocks:
            if block.getName() in target_sections or block.isExecute():
                extractor = OpcodeExtractor(block)
                thread = Thread(extractor)
                threads.append(thread)
                thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Write opcodes to the file in the original section order
        with open(output_file_path, "a") as output_file:
            for block in memory_blocks:
                section_name = block.getName()
                if section_name in target_sections or block.isExecute():
                    opcodes = section_opcodes.get(section_name, [])
                    print("Section Completed for {}: {}".format(base_name, section_name))
                    for opcode in opcodes:
                        output_file.write("{}\n".format(opcode))

        print("Opcode extraction complete. Results saved to:", output_file_path)

    except Exception as e:
        print("Error during opcode extraction:", str(e))

# Run the extraction function
extract_opcodes()

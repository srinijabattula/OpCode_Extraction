from ghidra.program.model.listing import Instruction
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util import Msg
import os
api = FlatProgramAPI(currentProgram)
input_file_name = currentProgram.getExecutablePath()
base_name = os.path.basename(input_file_name)
output_file_path = "/home/kali/Downloads/Opcode/{}_opcode.txt".format(base_name)
print("Extracting OpCode")
def is_code_section(block):
""" Check if a memory block likely contains code. """
return block.isExecute() and ("text" in block.getName().lower() or "code" in
block.getName().lower())
def extract_opcodes():
try:
with open(output_file_path, "w") as output_file:
memory_blocks = api.getMemoryBlocks()
code_blocks = [block for block in memory_blocks if is_code_section(block)]
if not code_blocks:
print("Error: No executable code section found in the binary.")
return
print("Found code sections:", [block.getName() for block in code_blocks])
for code_section in code_blocks:
start_address = code_section.getStart()
end_address = code_section.getEnd()
print("Processing section:", code_section.getName())
print("Section start address:", start_address)
print("Section end address:", end_address)
# Iterate over each instruction in the code section
current_address = start_address
while current_address < end_address:
instr = api.getInstructionAt(current_address)
# Use fallback if no instruction is found
if instr is None:
instr = api.getInstructionAfter(current_address)
if instr is None:
print("No further instructions found. Stopping extraction for this section.")
break
# Only write if we have a valid instructionopcode = instr.getMnemonicString()
if opcode:
output_file.write(opcode + "\n")
else:
print("Empty opcode found at address:", instr.getAddress())
# Move to the next address
current_address = instr.getAddress().add(instr.getLength())
print("Opcodes successfully extracted to {}".format(output_file_path))
except Exception as e:
print("Error during opcode extraction: {}".format(str(e)))
# Run the extraction function
extract_opcodes()

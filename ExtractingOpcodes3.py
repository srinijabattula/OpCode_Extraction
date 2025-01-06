from ghidra.program.model.listing import Instruction
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util import Msg
import os
# Initialize FlatProgramAPI
api = FlatProgramAPI(currentProgram)
# Define output file name
input_file_name = currentProgram.getExecutablePath()
base_name = os.path.basename(input_file_name)
output_file_path = "/home/kali/Downloads/Opcode/{}_opcode.txt".format(base_name)
print("Extracting OpCodes from executable sections")
def is_relevant_section(block):
""" Check if a memory block is relevant for opcode extraction. """
# Check if the section is executable and has one of the known names
section_name = block.getName().lower()
return block.isExecute() and (".text" in section_name or ".rsrc" in section_name or ".reloc"
in section_name or "debug" in section_name)
def extract_opcodes():
try:
with open(output_file_path, "w") as output_file:
memory_blocks = api.getMemoryBlocks()relevant_blocks = [block for block in memory_blocks if is_relevant_section(block)]
if not relevant_blocks:
print("Error: No executable code sections found in the binary.")
return
print("Found relevant code sections:", [block.getName() for block in relevant_blocks])
# Iterate over each relevant section
for code_section in relevant_blocks:
start_address = code_section.getStart()
end_address = code_section.getEnd()
print("Processing section:", code_section.getName())
print("Section start address:", start_address)
print("Section end address:", end_address)
# Linear sweep through each address in the section
current_address = start_address
while current_address < end_address:
instr = api.getInstructionAt(current_address)
# Move to the next address if no valid instruction is found
if instr is None:
current_address = current_address.add(1)
continue
# Write valid opcode to file
opcode = instr.getMnemonicString()
if opcode:
output_file.write(opcode + "\n")
else:
print("Empty opcode found at address:", instr.getAddress())
# Move to the next instruction
current_address = instr.getAddress().add(instr.getLength())
print("Opcodes successfully extracted to {}".format(output_file_path))
except Exception as e:
print("Error during opcode extraction: {}".format(str(e)))
# Run the extraction function
extract_opcodes()

import os
def get_output_file_path(input_path, output_dir):
    """
    Generate the output file path based on the input file and output directory.

    Args:
        input_path (str): Full path to the input binary.
        output_dir (str): Directory where output file will be saved.

    Returns:
        str: Full path for the opcode output file.
    """
    base_name = os.path.basename(input_path)
    return os.path.join(output_dir, f"{base_name}_opcode.txt")
def is_target_section(section_name, target_sections):
    """
    Check if a given section name is in the list of target sections.

    Args:
        section_name (str): Memory section name.
        target_sections (list of str): List of section names to match against.

    Returns:
        bool: True if section_name matches one of the target_sections (case-insensitive).
    """
    return section_name.lower() in (name.lower() for name in target_sections)

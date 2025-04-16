def parse_cisco_config(config_file):
    """Parse a Cisco configuration file into sections."""
    with open(config_file, 'r') as f:
        config_text = f.read()
    
    # Split into sections
    sections = {}
    current_section = "global"
    sections[current_section] = []
    
    for line in config_text.split('\n'):
        line = line.strip()
        if line.startswith('interface') or line.startswith('router'):
            current_section = line
            sections[current_section] = []
        elif line:
            sections[current_section].append(line)
    
    return sections
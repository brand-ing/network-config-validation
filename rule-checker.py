def check_telnet(config_sections):
    """Check if telnet is enabled."""
    vulnerabilities = []
    
    # Check for telnet enabled
    if 'transport input telnet' in str(config_sections):
        vulnerabilities.append({
            'severity': 'High',
            'description': 'Telnet is enabled, which transmits data in cleartext',
            'recommendation': 'Disable Telnet and enable SSH instead'
        })
    
    # Check for missing SSH
    if 'transport input ssh' not in str(config_sections):
        vulnerabilities.append({
            'severity': 'Medium',
            'description': 'SSH is not explicitly enabled',
            'recommendation': 'Configure SSH for secure management access'
        })
    
    return vulnerabilities
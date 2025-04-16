"""
ACORN: AI Configuration Oversight for Router Networks
Rule-based security checkers
"""

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

def check_password(config_sections):
    """Check password security configurations."""
    vulnerabilities = []
    
    # Global section checks
    global_config = config_sections.get('global', [])
    global_text = '\n'.join(global_config)
    
    # Check for weak password encryption
    if 'enable password' in global_text and 'enable secret' not in global_text:
        vulnerabilities.append({
            'severity': 'High',
            'description': 'Using weak "enable password" instead of "enable secret"',
            'recommendation': 'Configure "enable secret" instead of "enable password"'
        })
    
    # Check for password complexity requirements
    if 'password strength-check' not in global_text:
        vulnerabilities.append({
            'severity': 'Medium',
            'description': 'Password strength checking is not enabled',
            'recommendation': 'Enable "password strength-check" for password complexity requirements'
        })
    
    # Check for minimum password length
    if not any('security passwords min-length' in line for line in global_config):
        vulnerabilities.append({
            'severity': 'Medium',
            'description': 'Minimum password length is not configured',
            'recommendation': 'Configure "security passwords min-length 8" or higher'
        })
    
    return vulnerabilities

def check_acl(config_sections):
    """Check Access Control List configurations."""
    vulnerabilities = []
    
    # Check for permissive ACLs
    for section, lines in config_sections.items():
        section_text = '\n'.join(lines)
        
        # Check for "permit any any" in ACLs
        if 'access-list' in section and 'permit any any' in section_text:
            vulnerabilities.append({
                'severity': 'High',
                'description': f'Overly permissive ACL found in {section}',
                'recommendation': 'Restrict access to only necessary sources and destinations'
            })
        
        # Check for missing inbound filters on interfaces
        if section.startswith('interface') and 'ip access-group' not in section_text:
            # Exclude non-IP interfaces like loopbacks
            if not any(word in section for word in ['Loopback', 'Null']):
                vulnerabilities.append({
                    'severity': 'Medium',
                    'description': f'No inbound access list applied to {section}',
                    'recommendation': 'Apply appropriate access list with "ip access-group" command'
                })
    
    return vulnerabilities

def check_snmp(config_sections):
    """Check SNMP security configurations."""
    vulnerabilities = []
    
    global_config = '\n'.join(config_sections.get('global', []))
    
    # Check for SNMP v1/v2 (community strings)
    if 'snmp-server community' in global_config:
        vulnerabilities.append({
            'severity': 'High', 
            'description': 'Using insecure SNMP v1/v2c with community strings',
            'recommendation': 'Configure SNMPv3 with authentication and encryption'
        })
    
    # Check for missing SNMP ACLs
    if 'snmp-server community' in global_config and 'snmp-server community' in global_config and 'rw' in global_config:
        if not any('snmp-server community' in line and 'access' in line for line in config_sections.get('global', [])):
            vulnerabilities.append({
                'severity': 'High',
                'description': 'SNMP community strings without ACL restrictions',
                'recommendation': 'Apply ACLs to restrict SNMP access to trusted management stations'
            })
    
    # Check for public/private community strings
    common_strings = ['public', 'private', 'cisco', 'admin', 'snmp']
    for line in config_sections.get('global', []):
        if 'snmp-server community' in line:
            for common in common_strings:
                if common in line:
                    vulnerabilities.append({
                        'severity': 'High',
                        'description': f'Using common/default SNMP community string "{common}"',
                        'recommendation': 'Use strong, unique community strings or migrate to SNMPv3'
                    })
    
    return vulnerabilities

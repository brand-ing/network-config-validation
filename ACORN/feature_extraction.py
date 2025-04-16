"""
ACORN: AI Configuration Oversight for Router Networks
Feature extraction for machine learning
"""

def extract_features(config_sections):
    """
    Extract numerical features from router configuration for machine learning.
    
    Args:
        config_sections: Dictionary of configuration sections from parser
        
    Returns:
        Dictionary of features
    """
    features = {
        # Authentication features
        'password_type': 0,  # 0=clear, 1=type7, 2=type5, 3=type8/9
        'min_password_length': 0,
        'password_strength_check': 0,
        'aaa_new_model': 0,
        'local_usernames': 0,
        
        # Management protocol features
        'telnet_enabled': 0,
        'ssh_enabled': 0,
        'ssh_version': 1,  # Default to v1
        'https_enabled': 0,
        'http_enabled': 0,
        
        # SNMP features
        'snmpv3_only': 0,
        'weak_snmp': 0,
        'snmp_acl': 0,
        
        # Access control features
        'acl_count': 0,
        'interface_acl_count': 0,
        'has_strict_acls': 0,
        
        # Logging features
        'logging_enabled': 0,
        'syslog_servers': 0,
        
        # Service features
        'unused_services_disabled': 0,
        'tcp_keepalives': 0,
        
        # Control plane features
        'control_plane_protection': 0,
    }
    
    # Extract text for global config
    global_text = '\n'.join(config_sections.get('global', []))
    
    # ----- Password features -----
    # Check password encryption type
    if 'enable secret' in global_text:
        features['password_type'] = 2  # Type 5 (MD5)
        if 'enable secret 8' in global_text or 'enable secret 9' in global_text:
            features['password_type'] = 3  # Type 8/9 (PBKDF2/scrypt)
    elif 'enable password 7' in global_text:
        features['password_type'] = 1  # Type 7 (weak)
    
    # Check for password minimum length
    for line in config_sections.get('global', []):
        if 'security passwords min-length' in line:
            try:
                # Extract the number from the line
                features['min_password_length'] = int(line.split()[-1])
            except (IndexError, ValueError):
                pass
    
    # Check password strength enforcement
    features['password_strength_check'] = 1 if 'password strength-check' in global_text else 0
    
    # Check AAA
    features['aaa_new_model'] = 1 if 'aaa new-model' in global_text else 0
    
    # Count local usernames
    username_count = sum(1 for line in config_sections.get('global', []) if line.startswith('username'))
    features['local_usernames'] = min(username_count, 10)  # Cap at 10 to avoid outliers
    
    # ----- Management protocol features -----
    # Check for telnet/SSH
    for section, lines in config_sections.items():
        section_text = '\n'.join(lines)
        if 'transport input' in section_text:
            features['telnet_enabled'] = 1 if 'telnet' in section_text else 0
            features['ssh_enabled'] = 1 if 'ssh' in section_text else 0
    
    # Check SSH version
    for line in config_sections.get('global', []):
        if 'ip ssh version' in line:
            try:
                features['ssh_version'] = int(line.split()[-1])
            except (IndexError, ValueError):
                features['ssh_version'] = 1
    
    # Check HTTP/HTTPS
    features['http_enabled'] = 1 if 'ip http server' in global_text else 0
    features['https_enabled'] = 1 if 'ip http secure-server' in global_text else 0
    
    # ----- SNMP features -----
    snmpv3_found = any('snmp-server group' in line for line in config_sections.get('global', []))
    snmpv12_found = any('snmp-server community' in line for line in config_sections.get('global', []))
    
    features['snmpv3_only'] = 1 if (snmpv3_found and not snmpv12_found) else 0
    features['weak_snmp'] = 1 if snmpv12_found else 0
    
    # Check for SNMP ACLs
    features['snmp_acl'] = 1 if any('snmp-server community' in line and 'access' in line 
                                    for line in config_sections.get('global', [])) else 0
    
    # ----- ACL features -----
    acl_count = 0
    strict_acls = False
    interface_acl_count = 0
    
    for section, lines in config_sections.items():
        section_text = '\n'.join(lines)
        
        # Count ACLs in global config
        if section == 'global':
            acl_count = sum(1 for line in lines if line.startswith('access-list'))
            
            # Check for strict ACLs (deny any any)
            strict_acls = any('deny any any' in line for line in lines)
        
        # Count interfaces with ACLs applied
        if section.startswith('interface') and 'ip access-group' in section_text:
            interface_acl_count += 1
    
    features['acl_count'] = min(acl_count, 20)  # Cap at 20 to avoid outliers
    features['has_strict_acls'] = 1 if strict_acls else 0
    features['interface_acl_count'] = min(interface_acl_count, 10)  # Cap at 10
    
    # ----- Logging features -----
    features['logging_enabled'] = 1 if 'logging' in global_text else 0
    features['syslog_servers'] = min(
        sum(1 for line in config_sections.get('global', []) if 'logging host' in line), 
        5  # Cap at 5
    )
    
    # ----- Service features -----
    # Check for disabled services (positive security model)
    service_lines = [line for line in config_sections.get('global', []) if line.startswith('no service')]
    features['unused_services_disabled'] = min(len(service_lines), 5)  # Cap at 5
    
    # Check for TCP keepalives
    features['tcp_keepalives'] = 1 if 'service tcp-keepalives' in global_text else 0
    
    # ----- Control plane features -----
    features['control_plane_protection'] = 1 if 'control-plane' in config_sections else 0
    
    return features

def generate_training_data(config_files, labeled_secure=None):
    """
    Generate training data from a set of configuration files.
    
    Args:
        config_files: List of configuration file paths
        labeled_secure: Dictionary mapping filename to boolean (secure/insecure)
        
    Returns:
        Pandas DataFrame with features and target labels
    """
    import pandas as pd
    from parser import parse_cisco_config
    
    data = []
    
    for config_file in config_files:
        # Parse config
        config_sections = parse_cisco_config(config_file)
        
        # Extract features
        features = extract_features(config_sections)
        
        # Add filename and security label if available
        filename = os.path.basename(config_file)
        features['filename'] = filename
        
        if labeled_secure is not None and filename in labeled_secure:
            features['secure'] = int(labeled_secure[filename])
        
        data.append(features)
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    return df

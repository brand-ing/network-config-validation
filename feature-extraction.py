def extract_features(config_sections):
    """Extract features for machine learning from configuration."""
    features = {
        'password_type': 0,  # 0=clear, 1=type7, 2=type5, 3=type8/9
        'telnet_enabled': 0,
        'ssh_enabled': 0,
        'weak_snmp': 0,
        'acl_count': 0,
        # Add more features
    }
    
    # Example feature extraction
    if 'enable secret' in str(config_sections):
        features['password_type'] = 2
    elif 'enable password 7' in str(config_sections):
        features['password_type'] = 1
    
    # Extract more features similarly
    
    return features
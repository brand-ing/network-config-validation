#!/usr/bin/env python3
"""
ACORN: Quick Test Dataset Generator

This script generates a test dataset with the correct features
to use with the ml_pipeline.py script.
"""

import os
import pandas as pd
import numpy as np
import random

def generate_test_dataset(output_csv="test_features.csv", num_samples=100):
    """Generate a synthetic dataset with all required features."""
    
    # Define all the features that should be present
    features = {
        'password_type': [0, 1, 2, 3],         # 0=clear, 1=type7, 2=type5, 3=type8/9
        'telnet_enabled': [0, 1],              # 0=disabled, 1=enabled
        'ssh_enabled': [0, 1],                 # 0=disabled, 1=enabled
        'weak_snmp': [0, 1],                   # 0=no, 1=yes
        'acl_count': list(range(0, 11)),       # 0-10 ACLs
        'min_password_length': [0, 8, 10, 12], # Minimum password length
        'password_strength_check': [0, 1],     # 0=disabled, 1=enabled
        'aaa_new_model': [0, 1],               # 0=disabled, 1=enabled
        'local_usernames': list(range(0, 5)),  # 0-4 usernames
        'ssh_version': [1, 2],                 # SSH version
        'https_enabled': [0, 1],               # 0=disabled, 1=enabled
        'http_enabled': [0, 1],                # 0=disabled, 1=enabled
        'snmpv3_only': [0, 1],                 # 0=no, 1=yes
        'snmp_acl': [0, 1],                    # 0=no ACL, 1=has ACL
        'interface_acl_count': list(range(0, 5)), # 0-4 interfaces with ACLs
        'has_strict_acls': [0, 1],             # 0=no, 1=yes
        'logging_enabled': [0, 1],             # 0=disabled, 1=enabled
        'syslog_servers': list(range(0, 3)),   # 0-2 syslog servers
        'unused_services_disabled': list(range(0, 5)), # 0-4 disabled services
        'tcp_keepalives': [0, 1],              # 0=disabled, 1=enabled
        'control_plane_protection': [0, 1],    # 0=disabled, 1=enabled
    }
    
    # Create data array
    data = []
    
    for i in range(num_samples):
        # Create a random sample
        sample = {}
        
        for feature, values in features.items():
            sample[feature] = random.choice(values)
        
        # Generate filename
        sample['filename'] = f"router_{i:03d}.conf"
        
        # Generate secure label (based on feature values for realism)
        # More secure configurations have higher values for security features
        security_score = (
            (sample['ssh_enabled'] and not sample['telnet_enabled']) * 2 +
            (sample['password_type'] >= 2) * 2 +
            (sample['weak_snmp'] == 0) * 1.5 +
            (sample['acl_count'] > 3) * 1 +
            (sample['password_strength_check']) * 1 +
            (sample['min_password_length'] >= 10) * 1 +
            (sample['ssh_version'] == 2) * 1 +
            (not sample['http_enabled']) * 0.5 +
            (sample['https_enabled']) * 0.5 +
            (sample['snmpv3_only']) * 1 +
            (sample['logging_enabled']) * 0.5
        )
        
        # Convert to binary (1 = secure, 0 = insecure)
        sample['secure'] = 1 if security_score > 6 else 0
        
        data.append(sample)
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Print DataFrame info
    print(f"Created synthetic dataset with {num_samples} samples")
    print(f"DataFrame shape: {df.shape}")
    print(f"DataFrame columns: {df.columns.tolist()}")
    print(f"Secure samples: {df['secure'].sum()} ({df['secure'].sum()/len(df)*100:.1f}%)")
    
    # Save to CSV
    df.to_csv(output_csv, index=False)
    print(f"Saved dataset to {output_csv}")
    
    return df

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate a synthetic dataset for testing")
    parser.add_argument("--output", "-o", default="test_features.csv", help="Output CSV file")
    parser.add_argument("--samples", "-n", type=int, default=100, help="Number of samples to generate")
    
    args = parser.parse_args()
    
    # Generate the dataset
    generate_test_dataset(args.output, args.samples)

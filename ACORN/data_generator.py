#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
Training Data Generation Script

This script creates synthetic Cisco router configurations 
with varying security levels for training the ML model.
"""

import os
import random
import argparse
import pandas as pd
from ACORN.feature_extraction import extract_features
from ACORN.parser import parse_cisco_config

# Directory for generated configs
CONFIG_DIR = "training_configs"

def generate_password_section(secure=False):
    """Generate password configurations with varying security."""
    lines = []
    
    if secure:
        # Secure password configuration
        lines.append("service password-encryption")
        lines.append("enable secret $1$Csco$f6DlbHLeW/iF6DN9QOfJz1")  # Type 5 hash
        lines.append("security passwords min-length 12")
        lines.append("password strength-check")
    else:
        # Choose a weak password config
        if random.random() < 0.7:  # 70% chance of very weak
            lines.append("enable password cisco")  # Clear text
        else:
            # Type 7 (weak encryption)
            lines.append("enable password 7 02050D480809")
    
    # Add some username configurations
    if secure:
        # Strong username config
        lines.append("username admin privilege 15 secret $1$MzVl$hO37BzZ6R.e4SE6Xbx1i..")
        if random.random() < 0.7:
            lines.append("username operator privilege 5 secret $1$xjNM$UhEq8.2ygpmCxhxPFxP0M0")
    else:
        # Weak username config
        weak_passwords = ["cisco", "admin", "password", "router"]
        lines.append(f"username admin password {random.choice(weak_passwords)}")
    
    return lines

def generate_management_section(secure=False):
    """Generate management access configurations."""
    lines = []
    
    if secure:
        # Secure management
        lines.append("ip ssh version 2")
        lines.append("ip ssh authentication-retries 3")
        lines.append("ip ssh time-out 60")
        
        # Disable HTTP for secure configs
        lines.append("no ip http server")
        
        # Maybe enable HTTPS
        if random.random() < 0.7:
            lines.append("ip http secure-server")
            lines.append("ip http access-class 99")
    else:
        # Insecure management
        if random.random() < 0.7:
            lines.append("ip http server")  # Insecure HTTP
        
        # 50% chance of having SSH but with possible issues
        if random.random() < 0.5:
            lines.append("ip ssh version 2")
        else:
            # Might have v1 or no explicit version
            if random.random() < 0.5:
                lines.append("ip ssh version 1")
    
    return lines

def generate_snmp_section(secure=False):
    """Generate SNMP configurations."""
    lines = []
    
    if secure:
        # SNMPv3 with authentication and privacy
        lines.append("snmp-server group ADMIN v3 priv")
        lines.append("snmp-server user SNMPADMIN ADMIN v3 auth sha Auth123! priv aes 128 Priv123!")
    else:
        # Insecure SNMP v1/v2c
        common_communities = ["public", "private", "cisco", "community", "snmp"]
        
        # Choose a weak community string
        community = random.choice(common_communities)
        lines.append(f"snmp-server community {community} RO")
        
        # Sometimes add a read-write community
        if random.random() < 0.3:
            lines.append(f"snmp-server community {community}_rw RW")
    
    return lines

def generate_acl_section(secure=False):
    """Generate Access Control Lists."""
    lines = []
    
    if secure:
        # Management ACL 
        lines.append("ip access-list standard 99")
        lines.append(" permit 10.1.1.0 0.0.0.255")  # Internal management network
        lines.append(" deny any log")
        
        # Extended ACL for external interface
        lines.append("ip access-list extended EXTERNAL_IN")
        lines.append(" deny ip any host 10.1.1.1")  # Block direct access to router
        lines.append(" permit tcp any established")  # Allow return traffic
        lines.append(" permit icmp any any echo-reply")  # Allow ping replies
        lines.append(" permit icmp any any ttl-exceeded")  # Allow traceroute
        lines.append(" deny ip any any log")  # Log everything else
    else:
        # Potentially problematic ACLs
        if random.random() < 0.4:
            # Very permissive ACL 
            lines.append("ip access-list extended OPEN_ACCESS")
            lines.append(" permit ip any any")
        else:
            # Some attempt at restriction but with problems
            lines.append("ip access-list extended LIMITED_ACCESS")
            lines.append(" deny ip host 1.2.3.4 any")  # Block single IP
            lines.append(" permit ip any any")  # But allow everything else
    
    return lines

def generate_logging_section(secure=False):
    """Generate logging configurations."""
    lines = []
    
    # Basic logging
    lines.append("logging buffered 16384")
    
    if secure:
        # Secure logging
        lines.append("logging trap informational")
        lines.append("logging facility local6")
        lines.append("logging source-interface Loopback0")
        lines.append("logging host 10.1.1.100")
        
        # Sometimes add a second log server
        if random.random() < 0.6:
            lines.append("logging host 10.1.1.101")
    else:
        # Minimal logging
        if random.random() < 0.5:
            lines.append("logging trap notifications")  # Higher threshold, less logs
    
    return lines

def generate_services_section(secure=False):
    """Generate service configurations."""
    lines = []
    
    if secure:
        # Disable unnecessary services
        lines.append("no service pad")
        lines.append("no service udp-small-servers")
        lines.append("no service tcp-small-servers")
        lines.append("no ip bootp server")
        lines.append("no ip source-route")
        lines.append("no ip proxy-arp")
        lines.append("service tcp-keepalives-in")
        lines.append("service tcp-keepalives-out")
    else:
        # Leave most services enabled (default)
        if random.random() < 0.2:
            lines.append("service tcp-small-servers")  # Explicitly enable unnecessary service
    
    return lines

def generate_interface_section(name, secure=False):
    """Generate interface configuration."""
    lines = []
    
    lines.append(f"interface {name}")
    
    if "FastEthernet" in name or "GigabitEthernet" in name:
        # Set description
        if "0/0" in name:
            lines.append(" description External Interface")
        else:
            lines.append(" description Internal Interface")
        
        # IP configuration
        if "0/0" in name:
            lines.append(" ip address 203.0.113.1 255.255.255.0")
        else:
            lines.append(" ip address 10.1.1.1 255.255.255.0")
        
        # Security settings
        if secure:
            # Apply ACL if external interface
            if "0/0" in name:
                lines.append(" ip access-group EXTERNAL_IN in")
            
            # No CDP on external interfaces
            if "0/0" in name:
                lines.append(" no cdp enable")
            
            # Port security
            lines.append(" switchport port-security")
            lines.append(" switchport port-security maximum 2")
            
            # Disable proxy-arp
            lines.append(" no ip proxy-arp")
        else:
            # No security measures, or incomplete ones
            pass
        
        # Line protocol
        lines.append(" no shutdown")
    
    return lines

def generate_line_section(secure=False):
    """Generate line configuration (console, vty)."""
    lines = []
    
    # Console line
    lines.append("line console 0")
    if secure:
        lines.append(" login authentication CONSOLE")
        lines.append(" exec-timeout 10 0")  # 10 minute timeout
    else:
        if random.random() < 0.6:
            lines.append(" no login")  # No authentication
        else:
            lines.append(" exec-timeout 0 0")  # No timeout
    
    # VTY lines (telnet/ssh)
    lines.append("line vty 0 4")
    if secure:
        lines.append(" login authentication VTY")
        lines.append(" transport input ssh")  # SSH only
        lines.append(" exec-timeout 5 0")  # 5 minute timeout
        lines.append(" access-class 99 in")  # Apply ACL
    else:
        if random.random() < 0.4:
            lines.append(" transport input telnet ssh")  # Allow telnet
        elif random.random() < 0.7:
            lines.append(" transport input all")  # Allow all protocols
        
        if random.random() < 0.5:
            lines.append(" no login")  # No authentication
    
    return lines

def generate_router_config(filename, secure_probability=0.5):
    """Generate a complete router configuration file."""
    is_secure = random.random() < secure_probability
    
    lines = ["!"]
    lines.append("! Generated router configuration for ACORN training")
    lines.append("! Security level: " + ("SECURE" if is_secure else "INSECURE"))
    lines.append("!")
    
    # Generate various configuration sections
    lines.extend(generate_password_section(is_secure))
    lines.append("!")
    lines.extend(generate_management_section(is_secure))
    lines.append("!")
    lines.extend(generate_snmp_section(is_secure))
    lines.append("!")
    lines.extend(generate_acl_section(is_secure))
    lines.append("!")
    lines.extend(generate_logging_section(is_secure))
    lines.append("!")
    lines.extend(generate_services_section(is_secure))
    lines.append("!")
    
    # Generate interfaces
    for i in range(2):
        lines.extend(generate_interface_section(f"GigabitEthernet0/{i}", is_secure))
        lines.append("!")
    
    # Generate line configuration
    lines.extend(generate_line_section(is_secure))
    lines.append("!")
    lines.append("end")
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    # Write to file
    with open(filename, 'w') as f:
        f.write('\n'.join(lines))
    
    return is_secure

def generate_dataset(num_configs, output_csv="config_features.csv"):
    """Generate a dataset of router configurations with features and labels."""
    # Make sure directory exists
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    # Generate configs with varying security
    security_labels = {}
    
    for i in range(num_configs):
        filename = os.path.join(CONFIG_DIR, f"router_{i:03d}.conf")
        
        # Decide if this should be a secure or insecure config
        # Use balanced dataset (50/50)
        is_secure = generate_router_config(filename, secure_probability=0.5)
        
        # Record the label
        security_labels[os.path.basename(filename)] = is_secure
    
    # Extract features from all configs
    from ACORN.parser import parse_cisco_config
    from ACORN.feature_extraction import extract_features
    
    data = []
    for filename in os.listdir(CONFIG_DIR):
        if filename.endswith('.conf'):
            filepath = os.path.join(CONFIG_DIR, filename)
            
            # Parse the config
            config_sections = parse_cisco_config(filepath)
            
            # Extract features
            features = extract_features(config_sections)
            
            # Add the label
            features['secure'] = int(security_labels[filename])
            
            # Add to dataset
            data.append(features)
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Save to CSV
    df.to_csv(output_csv, index=False)
    
    print(f"Generated {num_configs} configurations")
    print(f"Saved features and labels to {output_csv}")
    
    return df

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate training data for ACORN")
    parser.add_argument("--configs", type=int, default=100, help="Number of configurations to generate")
    parser.add_argument("--output", default="config_features.csv", help="Output CSV file")
    
    args = parser.parse_args()
    
    # Generate the dataset
    generate_dataset(args.configs, args.output)

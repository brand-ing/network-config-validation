#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
Main integration script

This script ties together all components of the ACORN system:
- Configuration parsing
- Feature extraction
- Rule-based security checks
- Machine learning security scoring
- Report generation
"""

import os
import glob
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Import local modules
from config_parser import parse_cisco_config
from feature_extraction import extract_features
from rule_checker import check_telnet, check_password, check_acl, check_snmp  # Import all rule checkers
from generate_report import generate_report

# Constants
MODEL_PATH = "security_model.pkl"
OUTPUT_DIR = "reports"



def analyze_config(config_file, model=None):
    """
    Analyze a single configuration file and generate a report.
    
    Args:
        config_file: Path to the configuration file
        model: Trained machine learning model (optional)
        
    Returns:
        Tuple of (report_text, vulnerabilities, security_score)
    """
    print(f"Analyzing {config_file}...")
    
    # Parse config into sections
    config_sections = parse_cisco_config(config_file)
    
    # Run all rule-based checks
    vulnerabilities = []
    vulnerabilities.extend(check_telnet(config_sections))
    vulnerabilities.extend(check_password(config_sections))
    vulnerabilities.extend(check_acl(config_sections))
    vulnerabilities.extend(check_snmp(config_sections))
    
    # Extract features for ML model
    features = extract_features(config_sections)
    
    # Calculate security score
    if model:
        # Get expected feature names from model
        if hasattr(model, 'feature_names_in_'):
            expected_features = model.feature_names_in_
            
            # Create DataFrame with expected features
            feature_df = pd.DataFrame({feature: [features.get(feature, 0)] for feature in expected_features})
        else:
            # If model doesn't have feature_names_in_, just use all extracted features
            feature_df = pd.DataFrame([features])
        
        # Get security score from model (probability of being secure)
        security_score = model.predict_proba(feature_df)[0][1] * 10
    else:
        # If no model provided, use simple heuristic based on vulnerability count and severity
        high_count = sum(1 for v in vulnerabilities if v['severity'] == 'High')
        med_count = sum(1 for v in vulnerabilities if v['severity'] == 'Medium')
        low_count = sum(1 for v in vulnerabilities if v['severity'] == 'Low')
        
        # Simple weighted score (lower is better)
        vuln_score = (high_count * 3) + (med_count * 2) + low_count
        
        # Convert to 0-10 scale (higher is better)
        security_score = max(0, 10 - vuln_score)
    
    # Generate report
    report = generate_report(config_file, vulnerabilities, security_score)
    
    return report, vulnerabilities, security_score

def train_model(training_data_path="config_features.csv"):
    """
    Train the security classification model.
    
    Args:
        training_data_path: Path to CSV with labeled security features
        
    Returns:
        Trained model
    """
    print(f"Training model from {training_data_path}...")
    
    # Load labeled data
    data = pd.read_csv(training_data_path)
    
    # Split features and target
    X = data.drop('secure', axis=1)
    y = data['secure']
    
    # Train model
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    accuracy = model.score(X_test, y_test)
    print(f"Model accuracy: {accuracy:.4f}")
    
    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    return model

def load_or_train_model():
    """Load existing model or train a new one if none exists."""
    if os.path.exists(MODEL_PATH):
        print(f"Loading existing model from {MODEL_PATH}...")
        with open(MODEL_PATH, 'rb') as f:
            return pickle.load(f)
    else:
        return train_model()

def batch_analyze(config_dir):
    """
    Analyze all configuration files in a directory.
    
    Args:
        config_dir: Directory containing configuration files
        
    Returns:
        List of report paths
    """
    # Load or train model
    model = load_or_train_model()
    
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Find all config files
    config_files = glob.glob(os.path.join(config_dir, "*.conf"))
    
    # Analyze each config file
    reports = []
    summary_data = []
    
    for config_file in config_files:
        # Get filename without path or extension
        base_name = os.path.splitext(os.path.basename(config_file))[0]
        
        # Analyze config
        report, vulns, score = analyze_config(config_file, model)
        
        # Save report
        report_path = os.path.join(OUTPUT_DIR, f"{base_name}_report.md")
        with open(report_path, 'w') as f:
            f.write(report)
        
        # Add to summary
        summary_data.append({
            'device': base_name,
            'score': score,
            'high_vulns': sum(1 for v in vulns if v['severity'] == 'High'),
            'medium_vulns': sum(1 for v in vulns if v['severity'] == 'Medium'),
            'low_vulns': sum(1 for v in vulns if v['severity'] == 'Low'),
        })
        
        reports.append(report_path)
    
    # Create summary report
    summary_df = pd.DataFrame(summary_data)
    summary_df = summary_df.sort_values('score')
    
    summary_report = "# ACORN Security Summary Report\n\n"
    summary_report += "## Devices by Security Score (Worst to Best)\n\n"
    
    # Add summary table
    summary_report += "| Device | Score | High Vulns | Medium Vulns | Low Vulns |\n"
    summary_report += "|--------|-------|------------|--------------|----------|\n"
    
    for _, row in summary_df.iterrows():
        summary_report += f"| {row['device']} | {row['score']:.2f} | {row['high_vulns']} | {row['medium_vulns']} | {row['low_vulns']} |\n"
    
    # Write summary report
    summary_path = os.path.join(OUTPUT_DIR, "summary_report.md")
    with open(summary_path, 'w') as f:
        f.write(summary_report)
    
    return reports + [summary_path]

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="ACORN: AI Configuration Oversight for Router Networks")
    parser.add_argument("--dir", "-d", help="Directory containing config files to analyze")
    parser.add_argument("--file", "-f", help="Single config file to analyze")
    parser.add_argument("--train", "-t", action="store_true", help="Train/retrain the model")
    
    args = parser.parse_args()
    
    if args.train:
        train_model()
    
    if args.file:
        model = load_or_train_model()
        report, _, _ = analyze_config(args.file, model)
        print(report)
    
    if args.dir:
        reports = batch_analyze(args.dir)
        print(f"Generated {len(reports)} reports in {OUTPUT_DIR}/")
    
    if not (args.train or args.file or args.dir):
        parser.print_help()

    

if __name__ == "__main__":
    main()

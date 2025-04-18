#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
LLM Integration Demo

This script demonstrates how to integrate the LLM advisor with the main ACORN system.
"""

import os
import sys
import argparse
import pandas as pd
import markdown
import webbrowser
from tempfile import NamedTemporaryFile

# Try different import variations to handle module naming
try:
    from cisco_parser import parse_cisco_config
except ImportError:
    try:
        from config_parser import parse_cisco_config
    except ImportError:
        from parser import parse_cisco_config

from feature_extraction import extract_features
from rule_checker import check_telnet, check_password, check_acl, check_snmp
from generate_report import generate_report
from llm_advisor import LLMAdvisor

def analyze_config_with_llm(config_file, model=None):
    """
    Analyze a configuration file with enhanced LLM recommendations.
    
    Args:
        config_file: Path to the configuration file
        model: Trained machine learning model (optional)
        
    Returns:
        Analysis results including LLM remediation plan
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
    
    # Calculate security score using the model if available
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
    
    # Generate basic report
    report = generate_report(config_file, vulnerabilities, security_score)
    
    # Initialize LLM advisor
    advisor = LLMAdvisor()
    
    # Generate LLM-enhanced remediation plan if advisor is available and vulnerabilities exist
    llm_remediation_plan = None
    if advisor.is_available() and vulnerabilities:
        print("Generating LLM-enhanced remediation plan...")
        llm_remediation_plan = advisor.generate_remediation_plan(config_sections, vulnerabilities)
    
    return {
        'vulnerabilities': vulnerabilities,
        'security_score': security_score,
        'report': report,
        'llm_remediation_plan': llm_remediation_plan
    }

def display_report_in_browser(report_text, llm_plan=None):
    """
    Display the report and LLM remediation plan in the browser.
    
    Args:
        report_text: Markdown formatted report
        llm_plan: LLM-generated remediation plan (optional)
    """
    # Create HTML with bootstrap styling
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ACORN Security Analysis</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ padding: 20px; }}
            .report-section {{ margin-bottom: 30px; }}
            .llm-section {{ 
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 5px;
                border-left: 5px solid #17a2b8;
                margin-top: 30px;
            }}
            .llm-header {{
                background-color: #17a2b8;
                color: white;
                padding: 10px 20px;
                border-radius: 5px 5px 0 0;
                margin-top: 30px;
                margin-bottom: 0;
            }}
            pre {{ 
                background-color: #f1f1f1; 
                padding: 10px; 
                border-radius: 5px;
                white-space: pre-wrap;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="report-section">
                {markdown.markdown(report_text)}
            </div>
            
            {f'''
            <h2 class="llm-header">LLM-Enhanced Remediation Plan</h2>
            <div class="llm-section">
                {markdown.markdown(llm_plan)}
            </div>
            ''' if llm_plan else ''}
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    
    # Create temporary HTML file
    with NamedTemporaryFile('w', delete=False, suffix='.html') as f:
        f.write(html_content)
        temp_file = f.name
    
    # Open in browser
    webbrowser.open('file://' + temp_file)
    
    print(f"Report opened in your browser. Temporary file: {temp_file}")

def main():
    """Main function for the LLM integration demo."""
    parser = argparse.ArgumentParser(description="ACORN LLM Integration Demo")
    parser.add_argument("--file", "-f", required=True, help="Configuration file to analyze")
    parser.add_argument("--model", "-m", default="security_model.pkl", help="Path to trained model file")
    parser.add_argument("--no-browser", action="store_true", help="Don't open the report in browser")
    
    args = parser.parse_args()
    
    # Check if config file exists
    if not os.path.exists(args.file):
        print(f"Error: Configuration file '{args.file}' not found.")
        sys.exit(1)
    
    # Load model if exists
    model = None
    if os.path.exists(args.model):
        import pickle
        with open(args.model, 'rb') as f:
            model = pickle.load(f)
        print(f"Loaded model from {args.model}")
    else:
        print(f"Warning: Model file '{args.model}' not found. Using heuristic scoring.")
    
    # Analyze config with LLM enhancement
    results = analyze_config_with_llm(args.file, model)
    
    # Display results
    print(f"\nSecurity Score: {results['security_score']:.2f}/10")
    print(f"Vulnerabilities Found: {len(results['vulnerabilities'])}")
    
    # Count vulnerabilities by severity
    high_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'High')
    med_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'Medium')
    low_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'Low')
    print(f"  High: {high_count}, Medium: {med_count}, Low: {low_count}")
    
    # Check if LLM remediation plan was generated
    if results['llm_remediation_plan']:
        print("\nLLM-Enhanced Remediation Plan generated successfully!")
    else:
        print("\nNo LLM-Enhanced Remediation Plan available.")
        if not os.getenv("OPENAI_API_KEY"):
            print("Tip: Set the OPENAI_API_KEY environment variable to enable LLM features.")
    
    # Display report in browser unless disabled
    if not args.no_browser:
        display_report_in_browser(results['report'], results['llm_remediation_plan'])
    else:
        # Print report to console
        print("\n" + "=" * 80)
        print(results['report'])
        if results['llm_remediation_plan']:
            print("\n" + "=" * 80)
            print("LLM-ENHANCED REMEDIATION PLAN:")
            print(results['llm_remediation_plan'])

if __name__ == "__main__":
    main()

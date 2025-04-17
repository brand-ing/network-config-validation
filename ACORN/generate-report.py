#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
Report Generator Module

This module generates markdown reports based on security analysis results.
"""

import datetime

def generate_report(config_file, vulnerabilities, model_score):
    """
    Generate a comprehensive security report in markdown format.
    
    Args:
        config_file: Name of the config file that was analyzed
        vulnerabilities: List of vulnerability dictionaries
        model_score: Overall security score (0-10)
        
    Returns:
        Markdown formatted report as a string
    """
    # Get current timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Count vulnerabilities by severity
    high_count = sum(1 for v in vulnerabilities if v['severity'] == 'High')
    medium_count = sum(1 for v in vulnerabilities if v['severity'] == 'Medium')
    low_count = sum(1 for v in vulnerabilities if v['severity'] == 'Low')
    
    # Determine security level based on score
    if model_score >= 7.5:
        security_level = "Good"
        level_description = "This configuration follows most security best practices."
    elif model_score >= 5:
        security_level = "Moderate"
        level_description = "This configuration has some security issues that should be addressed."
    else:
        security_level = "Poor"
        level_description = "This configuration has critical security issues that must be addressed immediately."
    
    # Build report header
    report = f"# Security Analysis Report for {config_file}\n\n"
    report += f"**Generated:** {timestamp}\n\n"
    report += f"## Overall Security Score: {model_score:.2f}/10\n\n"
    report += f"**Security Level:** {security_level}\n\n"
    report += f"{level_description}\n\n"
    
    # Summary section
    report += "## Executive Summary\n\n"
    
    if vulnerabilities:
        report += f"This analysis identified {len(vulnerabilities)} security vulnerabilities:\n"
        report += f"- **{high_count}** High severity issues\n"
        report += f"- **{medium_count}** Medium severity issues\n"
        report += f"- **{low_count}** Low severity issues\n\n"
        
        # Add key issues if high severity vulnerabilities exist
        if high_count > 0:
            report += "### Key Issues\n\n"
            high_vulns = [v for v in vulnerabilities if v['severity'] == 'High']
            for vuln in high_vulns[:3]:  # List up to 3 high severity issues
                report += f"- {vuln['description']}\n"
            report += "\n"
    else:
        report += "No security vulnerabilities were detected in this configuration.\n\n"
    
    # Detailed findings
    report += "## Detailed Findings\n\n"
    
    if vulnerabilities:
        # Group vulnerabilities by severity
        severities = ["High", "Medium", "Low"]
        
        for severity in severities:
            severity_vulns = [v for v in vulnerabilities if v['severity'] == severity]
            
            if severity_vulns:
                report += f"### {severity} Severity Issues\n\n"
                
                for i, vuln in enumerate(severity_vulns, 1):
                    report += f"#### {i}. {vuln['description']}\n\n"
                    report += f"**Recommendation:** {vuln['recommendation']}\n\n"
    else:
        report += "No vulnerabilities were identified in this configuration.\n\n"
    
    # Recommendations summary
    report += "## Recommendations Summary\n\n"
    
    if vulnerabilities:
        # High priority recommendations
        high_vulns = [v for v in vulnerabilities if v['severity'] == 'High']
        if high_vulns:
            report += "### High Priority (Address Immediately)\n\n"
            for vuln in high_vulns:
                report += f"- {vuln['recommendation']}\n"
            report += "\n"
        
        # Medium priority recommendations
        medium_vulns = [v for v in vulnerabilities if v['severity'] == 'Medium']
        if medium_vulns:
            report += "### Medium Priority (Address Soon)\n\n"
            for vuln in medium_vulns:
                report += f"- {vuln['recommendation']}\n"
            report += "\n"
        
        # Low priority recommendations
        low_vulns = [v for v in vulnerabilities if v['severity'] == 'Low']
        if low_vulns:
            report += "### Low Priority (Address When Convenient)\n\n"
            for vuln in low_vulns:
                report += f"- {vuln['recommendation']}\n"
            report += "\n"
    else:
        report += "No specific recommendations are necessary as no vulnerabilities were identified.\n\n"
    
    # Best practices section
    report += "## Best Practices\n\n"
    report += "Even if your configuration is secure, always follow these network security best practices:\n\n"
    report += "1. **Regular Audits**: Schedule periodic security audits of your network configurations\n"
    report += "2. **Change Management**: Implement strict change management procedures\n"
    report += "3. **Configuration Backups**: Maintain backups of all device configurations\n"
    report += "4. **Updates**: Keep device firmware and software up to date\n"
    report += "5. **Documentation**: Maintain accurate network documentation\n\n"
    
    # Footer
    report += "---\n"
    report += "Report generated by ACORN Security Analyzer\n"
    
    return report

if __name__ == "__main__":
    # Test the report generator with sample data
    sample_vulnerabilities = [
        {
            'severity': 'High',
            'description': 'Telnet is enabled, which transmits data in cleartext',
            'recommendation': 'Disable Telnet and enable SSH instead'
        },
        {
            'severity': 'Medium',
            'description': 'SSH is not explicitly enabled',
            'recommendation': 'Configure SSH for secure management access'
        },
        {
            'severity': 'Low',
            'description': 'Interface timeout not configured',
            'recommendation': 'Configure appropriate timeout values'
        }
    ]
    
    report = generate_report("sample_router.conf", sample_vulnerabilities, 6.5)
    print(report)
    
    # Save to file as an example
    with open("sample_report.md", "w") as f:
        f.write(report)
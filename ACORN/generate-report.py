def generate_report(config_file, vulnerabilities, model_score):
    """Generate a simple security report."""
    report = f"# Security Analysis for {config_file}\n\n"
    report += f"## Overall Security Score: {model_score:.2f}/10\n\n"
    
    report += "## Vulnerabilities Found:\n\n"
    for vuln in vulnerabilities:
        report += f"- **{vuln['severity']}**: {vuln['description']}\n"
        report += f"  - *Recommendation*: {vuln['recommendation']}\n\n"
    
    return report
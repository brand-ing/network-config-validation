#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
Web Interface for Demonstrations

This script creates a simple web UI for demonstrating the ACORN tool.
It allows users to upload config files, see vulnerabilities, and view security scores.
"""

import os
import pickle
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from flask import Flask, request, render_template_string, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile
import time
import base64
from io import BytesIO

# Import ACORN modules
try:
    from cisco_parser import parse_cisco_config  # Try the renamed version first
except ImportError:
    try:
        from config_parser import parse_cisco_config  # Try another common rename
    except ImportError:
        from parser import parse_cisco_config  # Fall back to original

from feature_extraction import extract_features
from rule_checker import check_telnet, check_password, check_acl, check_snmp
from generate_report import generate_report

# Constants
MODEL_PATH = "security_model.pkl"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'txt', 'conf', 'config'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size

# Create Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = 'acorn_security_tool'  # For flash messages

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load the model
def load_model():
    try:
        with open(MODEL_PATH, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        print(f"Model file not found at {MODEL_PATH}")
        return None
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Process a configuration file
def process_config(file_path):
    """Process a configuration file and return analysis results."""
    try:
        # Parse config into sections
        config_sections = parse_cisco_config(file_path)
        
        # Run rule-based checks
        vulnerabilities = []
        vulnerabilities.extend(check_telnet(config_sections))
        vulnerabilities.extend(check_password(config_sections))
        vulnerabilities.extend(check_acl(config_sections))
        vulnerabilities.extend(check_snmp(config_sections))
        
        # Extract features for ML model
        features = extract_features(config_sections)
        
        # Use model to predict security score if available
        model = load_model()
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
            security_score = float(model.predict_proba(feature_df)[0][1] * 10)
        else:
            # If no model available, use simple heuristic based on vulnerability count and severity
            high_count = sum(1 for v in vulnerabilities if v['severity'] == 'High')
            med_count = sum(1 for v in vulnerabilities if v['severity'] == 'Medium')
            low_count = sum(1 for v in vulnerabilities if v['severity'] == 'Low')
            
            # Simple weighted score (lower is better)
            vuln_score = (high_count * 3) + (med_count * 2) + low_count
            
            # Convert to 0-10 scale (higher is better)
            security_score = max(0, 10 - vuln_score)
        
        # Generate a report
        report = generate_report(os.path.basename(file_path), vulnerabilities, security_score)
        
        return {
            'vulnerabilities': vulnerabilities,
            'security_score': security_score,
            'report': report,
            'feature_importance_img': None
        }
    except Exception as e:
        print(f"Error processing configuration: {e}")
        return {
            'vulnerabilities': [{'severity': 'Error', 'description': f"Error processing configuration: {str(e)}", 'recommendation': 'Check file format and try again'}],
            'security_score': 0,
            'report': f"# Error Processing Configuration\n\nAn error occurred: {str(e)}",
            'feature_importance_img': None
        }

# Define HTML templates as strings to avoid file encoding issues
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACORN - Network Device Security Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .header-bg {
            background-color: #343a40;
            color: white;
            padding: 30px 0;
            margin-bottom: 30px;
        }
        .upload-container {
            max-width: 700px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .footer {
            margin-top: 50px;
            padding: 20px 0;
            background-color: #343a40;
            color: white;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header-bg">
        <div class="container">
            <h1>ACORN</h1>
            <h4>AI Configuration Oversight for Router Networks</h4>
        </div>
    </div>
    
    <div class="container">
        <div class="upload-container">
            <h2 class="mb-4">Upload Configuration File</h2>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <form action="/upload" method="post" enctype="multipart/form-data">
                <div class="mb-3">
                    <label for="configFile" class="form-label">Select a Cisco router/switch configuration file:</label>
                    <input class="form-control" type="file" id="configFile" name="file" required>
                    <div class="form-text">Supported file types: .conf, .txt, .config</div>
                </div>
                <button type="submit" class="btn btn-primary">Analyze Configuration</button>
            </form>
            
            <div class="mt-4">
                <h5>What this tool does:</h5>
                <ul>
                    <li>Parses network device configuration files</li>
                    <li>Identifies security vulnerabilities using rule-based checks</li>
                    <li>Scores overall security posture using machine learning</li>
                    <li>Provides actionable recommendations to improve security</li>
                </ul>
            </div>
        </div>
    </div>
    
    <footer class="footer">
        <div class="container">
            <p>ACORN - AI Configuration Oversight for Router Networks</p>
            <p>&copy; 2025 - Developed by Brandon I.</p>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

RESULTS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACORN - Analysis Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        .header-bg {
            background-color: #343a40;
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
        }
        .score-display {
            text-align: center;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        .high-score {
            background-color: #d4edda;
            color: #155724;
        }
        .medium-score {
            background-color: #fff3cd;
            color: #856404;
        }
        .low-score {
            background-color: #f8d7da;
            color: #721c24;
        }
        .footer {
            margin-top: 50px;
            padding: 20px 0;
            background-color: #343a40;
            color: white;
            text-align: center;
        }
        .vulnerability-card {
            margin-bottom: 15px;
        }
        .vulnerability-high {
            border-left: 5px solid #dc3545;
        }
        .vulnerability-medium {
            border-left: 5px solid #ffc107;
        }
        .vulnerability-low {
            border-left: 5px solid #17a2b8;
        }
        .report-container {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header-bg">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h1>ACORN</h1>
                    <h5>Analysis Results</h5>
                </div>
                <a href="/" class="btn btn-outline-light">
                    <i class="bi bi-upload"></i> Analyze Another Configuration
                </a>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="row">
            <div class="col-md-8">
                <h2>Security Analysis for: {{ filename }}</h2>
                
                <div class="score-display {% if score >= 7 %}high-score{% elif score >= 4 %}medium-score{% else %}low-score{% endif %}">
                    <h3>Overall Security Score</h3>
                    <h1 class="display-1">{{ "%.1f"|format(score) }}/10</h1>
                    <p>
                        {% if score >= 7 %}
                            <i class="bi bi-shield-check"></i> Good security practices detected
                        {% elif score >= 4 %}
                            <i class="bi bi-shield-exclamation"></i> Some security concerns identified
                        {% else %}
                            <i class="bi bi-shield-x"></i> Significant security issues detected
                        {% endif %}
                    </p>
                </div>
                
                <h3 class="mt-4">Vulnerabilities Found ({{ vulnerabilities|length }})</h3>
                {% if vulnerabilities %}
                    {% set high_count = vulnerabilities|selectattr('severity', 'equalto', 'High')|list|length %}
                    {% set medium_count = vulnerabilities|selectattr('severity', 'equalto', 'Medium')|list|length %}
                    {% set low_count = vulnerabilities|selectattr('severity', 'equalto', 'Low')|list|length %}
                    
                    <div class="mb-3">
                        <span class="badge bg-danger">{{ high_count }} High</span>
                        <span class="badge bg-warning text-dark">{{ medium_count }} Medium</span>
                        <span class="badge bg-info">{{ low_count }} Low</span>
                    </div>
                    
                    {% for vuln in vulnerabilities %}
                        <div class="card vulnerability-card vulnerability-{{ vuln.severity|lower }}">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-center">
                                    <h5 class="card-title">{{ vuln.description }}</h5>
                                    <span class="badge {% if vuln.severity == 'High' %}bg-danger{% elif vuln.severity == 'Medium' %}bg-warning text-dark{% else %}bg-info{% endif %}">
                                        {{ vuln.severity }}
                                    </span>
                                </div>
                                <p class="card-text"><strong>Recommendation:</strong> {{ vuln.recommendation }}</p>
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    <div class="alert alert-success">
                        <i class="bi bi-shield-check"></i> No vulnerabilities detected.
                    </div>
                {% endif %}
                
                <div class="report-container">
                    <h3>Security Report</h3>
                    <div id="report-content"></div>
                </div>
                
                <div class="mt-4">
                    <a href="/download-report/{{ filename }}" class="btn btn-success">
                        <i class="bi bi-file-earmark-text"></i> Download Report
                    </a>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5>Security Improvement Tips</h5>
                    </div>
                    <div class="card-body">
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <i class="bi bi-lock-fill text-primary"></i> Use strong password encryption with secret
                            </li>
                            <li class="list-group-item">
                                <i class="bi bi-shield-lock-fill text-primary"></i> Replace Telnet with SSH
                            </li>
                            <li class="list-group-item">
                                <i class="bi bi-filter-circle-fill text-primary"></i> Apply strict ACLs to all interfaces
                            </li>
                            <li class="list-group-item">
                                <i class="bi bi-diagram-3-fill text-primary"></i> Configure secure SNMPv3
                            </li>
                            <li class="list-group-item">
                                <i class="bi bi-clock-fill text-primary"></i> Set appropriate timeout values
                            </li>
                        </ul>
                    </div>
                </div>
                
                {% if feature_importance_img %}
                <div class="card mt-4">
                    <div class="card-header">
                        <h5>Feature Importance</h5>
                    </div>
                    <div class="card-body">
                        <img src="data:image/png;base64,{{ feature_importance_img }}" class="img-fluid" alt="Feature Importance">
                    </div>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <footer class="footer">
        <div class="container">
            <p>ACORN - AI Configuration Oversight for Router Networks</p>
            <p>&copy; 2025 - Developed by Brandon I.</p>
        </div>
    </footer>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const reportContent = document.getElementById('report-content');
            const report = `{{ report|safe }}`;
            reportContent.innerHTML = marked.parse(report);
        });
    </script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# Flask routes
@app.route('/')
def index():
    """Show the upload page."""
    return render_template_string(INDEX_HTML)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and process configuration."""
    # Check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    # If the user does not select a file, the browser submits an empty file without a filename
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Secure the filename
        filename = secure_filename(file.filename)
        
        # Create a timestamped version to avoid overwriting
        timestamp = int(time.time())
        filename_parts = os.path.splitext(filename)
        timestamped_filename = f"{filename_parts[0]}_{timestamp}{filename_parts[1]}"
        
        # Save the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], timestamped_filename)
        file.save(file_path)
        
        # Process the configuration
        results = process_config(file_path)
        
        # Store the report for download
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{timestamped_filename}.md")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(results['report'])
        
        # Render the results template
        return render_template_string(
            RESULTS_HTML, 
            filename=file.filename,  # Show original filename
            score=results['security_score'],
            vulnerabilities=results['vulnerabilities'],
            report=results['report'],
            feature_importance_img=results['feature_importance_img']
        )
    else:
        flash('File type not allowed. Please upload a .conf, .config, or .txt file.', 'danger')
        return redirect(url_for('index'))

@app.route('/download-report/<filename>')
def download_report(filename):
    """Download the generated report."""
    # Find the latest report for this filename
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    filename_base = os.path.splitext(filename)[0]
    report_files = [f for f in files if f.startswith(filename_base) and f.endswith('.md')]
    
    if report_files:
        # Get the most recent report
        latest_report = sorted(report_files)[-1]
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], latest_report)
        
        # Return the file
        return send_file(report_path, 
                         mimetype='text/markdown',
                         as_attachment=True,
                         download_name=f"{filename}_security_report.md")
    else:
        flash('Report not found', 'danger')
        return redirect(url_for('index'))

# Start the app if running directly
if __name__ == '__main__':
    print("Starting ACORN Web Interface...")
    print(f"Upload directory: {os.path.abspath(UPLOAD_FOLDER)}")
    print(f"Model path: {os.path.abspath(MODEL_PATH)}")
    print("Access the application at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
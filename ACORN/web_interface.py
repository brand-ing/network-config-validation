#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
Web Interface with Simple OpenAI Integration for Security Recommendations
"""

import os
import pickle
import pandas as pd
import json
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
import requests

# Add this right after your imports at the top of the file
def test_openai_connection():
    print("\n===== TESTING OPENAI CONNECTION =====")
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        print("ERROR: No OpenAI API key found in environment")
        return False
    
    print(f"API Key found (starts with: {api_key[:5]}...)")
    
    try:
        test_url = "https://api.openai.com/v1/chat/completions"
        test_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        test_data = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Say hello"}
            ],
            "max_tokens": 20
        }
        
        print("Sending test request to OpenAI API...")
        response = requests.post(
            test_url,
            headers=test_headers,
            json=test_data,
            timeout=10
        )
        
        print(f"Response status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            message = result["choices"][0]["message"]["content"]
            print(f"Received response: {message}")
            print("OpenAI API connection SUCCESSFUL")
            return True
        else:
            print(f"Error response: {response.text}")
            print("OpenAI API connection FAILED")
            return False
    
    except Exception as e:
        print(f"Exception during test: {str(e)}")
        print("OpenAI API connection FAILED")
        return False

# Add this at the end of your file, right before app.run()
connection_ok = test_openai_connection()
if not connection_ok:
    print("WARNING: OpenAI connection test failed. AI recommendations will not work.")
    print("Please check your API key and internet connection.")

os.environ["OPENAI_API_KEY"] = "your-openai-api-key" # here APPLE
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

# OpenAI integration settings
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = "gpt-3.5-turbo"

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
        
        # Generate AI recommendations based on vulnerabilities
        ai_recommendations = get_ai_recommendations(config_sections, vulnerabilities)
        
        # Generate a report
        report = generate_report(os.path.basename(file_path), vulnerabilities, security_score)
        
        return {
            'config_sections': config_sections,
            'vulnerabilities': vulnerabilities,
            'security_score': security_score,
            'report': report,
            'feature_importance_img': None,
            'ai_recommendations': ai_recommendations
        }
    except Exception as e:
        print(f"Error processing configuration: {e}")
        return {
            'config_sections': {},
            'vulnerabilities': [{'severity': 'Error', 'description': f"Error processing configuration: {str(e)}", 'recommendation': 'Check file format and try again'}],
            'security_score': 0,
            'report': f"# Error Processing Configuration\n\nAn error occurred: {str(e)}",
            'feature_importance_img': None,
            'ai_recommendations': ["Unable to generate AI recommendations due to processing error."]
        }

def get_ai_recommendations(config_sections, vulnerabilities):
    """Generate AI-powered security recommendations using OpenAI."""
    print("Starting AI recommendation generation...")
    if not OPENAI_API_KEY:
        print("ERROR: No OpenAI API key found")
        return ["API key not configured. Set OPENAI_API_KEY environment variable for AI recommendations."]
    
    try:
        # Prepare the vulnerabilities text
        vuln_text = ""
        for v in vulnerabilities:
            vuln_text += f"- {v['severity']}: {v['description']} (Recommended fix: {v['recommendation']})\n"
        
        # Prepare the system prompt
        system_prompt = """
        You are a network security expert specializing in Cisco device configurations. 
        Generate a prioritized list of actionable recommendations to improve the security of 
        the network device configuration. Focus on practical, specific advice that goes beyond 
        the basic rule-based checks already performed.
        
        Format each recommendation as:
        1. [TITLE]: Brief description of what to implement
           - Command: example command to use
           - Benefit: security benefit this provides
        
        Limit to 3-5 most important recommendations, ordered by security impact.
        """
        
        # Prepare user message
        user_message = f"""
        Here's the parsed network device configuration:
        {json.dumps(config_sections, indent=2)[:2000]}... (truncated)
        
        Vulnerabilities already identified by basic rule checks:
        {vuln_text}
        
        Please provide strategic security recommendations beyond these basic findings.
        """
        
        # Prepare API request - FIX: Define the headers here
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        
        print(f"Using API key: {OPENAI_API_KEY[:5]}...")  # Print first few chars of key for verification
        
        data = {
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": 800,
            "temperature": 0.7
        }
        
        # Make API request
        print("Sending request to OpenAI API...")
        response = requests.post(
            OPENAI_API_URL,
            headers=headers,
            json=data,
            timeout=30
        )
        
        # Handle response
        print(f"Received response with status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            recommendations = result["choices"][0]["message"]["content"].strip().split("\n")
            print("Successfully parsed recommendations")
            return recommendations
        else:
            print(f"OpenAI API error: {response.status_code} - {response.text}")
            return [f"Error generating AI recommendations: API returned status {response.status_code}"]
            
    except Exception as e:
        print(f"Error generating AI recommendations: {str(e)}")
        return [f"Error generating AI recommendations: {str(e)}"]

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
            feature_importance_img=results['feature_importance_img'],
            ai_recommendations=results['ai_recommendations']
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

# Define HTML templates as strings to avoid file encoding issues
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACORN - Network Device Security Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <style>
        .header-bg {
            background: linear-gradient(135deg, #343a40 0%, #212529 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .header-logo {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        .header-subtitle {
            font-size: 1.2rem;
            opacity: 0.8;
        }
        .upload-container {
            max-width: 700px;
            margin: 0 auto 40px;
            padding: 30px;
            background-color: #fff;
            border-radius: 12px;
            box-shadow: 0 6px 24px rgba(0,0,0,0.08);
        }
        .upload-title {
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: #343a40;
            font-weight: 600;
        }
        .upload-btn {
            margin-top: 10px;
            padding: 10px 20px;
            border-radius: 6px;
            background-color: #0d6efd;
            border: none;
            font-weight: 500;
            transition: all 0.2s;
        }
        .upload-btn:hover {
            background-color: #0b5ed7;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .feature-card {
            padding: 24px;
            background-color: #fff;
            border-radius: 12px;
            height: 100%;
            box-shadow: 0 4px 16px rgba(0,0,0,0.05);
            transition: all 0.3s;
        }
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.1);
        }
        .feature-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            background-color: #e7f1ff;
            color: #0d6efd;
            font-size: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
        }
        .feature-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 10px;
            color: #343a40;
        }
        .feature-text {
            color: #6c757d;
            font-size: 0.95rem;
            line-height: 1.5;
        }
        .footer {
            margin-top: 50px;
            padding: 30px 0;
            background-color: #343a40;
            color: white;
            text-align: center;
        }
        .new-badge {
            display: inline-block;
            background: linear-gradient(135deg, #3a86ff 0%, #0d6efd 100%);
            color: white;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 5px 10px;
            border-radius: 30px;
            margin-left: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="header-bg">
        <div class="container text-center">
            <div class="header-logo">ACORN</div>
            <div class="header-subtitle">AI Configuration Oversight for Router Networks</div>
        </div>
    </div>
    
    <div class="container">
        <div class="upload-container">
            <h2 class="upload-title">Upload Configuration File</h2>
            
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
                    <input class="form-control form-control-lg" type="file" id="configFile" name="file" required>
                    <div class="form-text">Supported file types: .conf, .txt, .config</div>
                </div>
                <button type="submit" class="btn btn-primary upload-btn">
                    <i class="bi bi-shield-lock"></i> Analyze Security
                </button>
            </form>
        </div>
        
        <div class="row g-4 mb-5">
            <div class="col-md-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="bi bi-shield-check"></i>
                    </div>
                    <h3 class="feature-title">Vulnerability Detection</h3>
                    <p class="feature-text">
                        Identifies security vulnerabilities in network device configurations using rule-based security checks and machine learning analysis.
                    </p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="bi bi-graph-up"></i>
                    </div>
                    <h3 class="feature-title">Security Scoring</h3>
                    <p class="feature-text">
                        Evaluates your overall security posture with a comprehensive scoring system based on industry best practices and security standards.
                    </p>
                </div>
            </div>
            <div class="col-md-4">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="bi bi-robot"></i>
                    </div>
                    <h3 class="feature-title">AI Recommendations <span class="new-badge">NEW</span></h3>
                    <p class="feature-text">
                        Leverages artificial intelligence to provide advanced, context-aware security recommendations tailored to your specific network configuration.
                    </p>
                </div>
            </div>
        </div>
    </div>
    
    <footer class="footer">
        <div class="container">
            <p class="mb-1">ACORN - AI Configuration Oversight for Router Networks</p>
            <p class="mb-0">&copy; 2025 - Developed by Brandon I.</p>
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
            background: linear-gradient(135deg, #343a40 0%, #212529 100%);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .score-display {
            text-align: center;
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.05);
        }
        .high-score {
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            color: #155724;
        }
        .medium-score {
            background: linear-gradient(135deg, #fff3cd 0%, #ffeeba 100%);
            color: #856404;
        }
        .low-score {
            background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
            color: #721c24;
        }
        .footer {
            margin-top: 50px;
            padding: 30px 0;
            background-color: #343a40;
            color: white;
            text-align: center;
        }
        .vulnerability-card {
            margin-bottom: 15px;
            border: none;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
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
            background-color: #fff;
            padding: 25px;
            border-radius: 12px;
            margin-top: 30px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.05);
        }
        .recommendation-card {
            border: none;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 16px rgba(0,0,0,0.05);
            margin-bottom: 20px;
            background-color: #fff;
        }
        .recommendation-header {
            background: linear-gradient(135deg, #4a6cf7 0%, #2440b3 100%);
            color: white;
            padding: 15px 20px;
        }
        .recommendation-title {
            margin: 0;
            font-size: 1.1rem;
            font-weight: 600;
        }
        .recommendation-body {
            padding: 20px;
        }
        .recommendation-content {
            white-space: pre-line;
            font-size: 0.95rem;
            line-height: 1.6;
        }
        .main-section-title {
            margin-bottom: 20px;
            font-weight: 600;
            color: #343a40;
            padding-bottom: 10px;
            border-bottom: 2px solid #e9ecef;
        }
        .download-btn {
            background-color: #28a745;
            border: none;
            border-radius: 6px;
            padding: 10px 20px;
            transition: all 0.2s;
        }
        .download-btn:hover {
            background-color: #218838;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .home-btn {
            background-color: transparent;
            border: 1px solid white;
            transition: all 0.2s;
        }
        .home-btn:hover {
            background-color: rgba(255,255,255,0.1);
            transform: translateY(-2px);
        }
        .ai-badge {
            display: inline-block;
            background: linear-gradient(135deg, #3a86ff 0%, #0d6efd 100%);
            color: white;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 30px;
            margin-right: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .command-box {
            background-color: #f8f9fa;
            border-left: 3px solid #6c757d;
            padding: 10px 15px;
            margin: 10px 0;
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            color: #212529;
        }
        .benefit-text {
            color: #28a745;
            font-weight: 500;
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
                <a href="/" class="btn btn-outline-light home-btn">
                    <i class="bi bi-upload"></i> Analyze Another Configuration
                </a>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="row">
            <div class="col-md-8">
                <h2 class="main-section-title">Security Analysis for: {{ filename }}</h2>
                
                <div class="score-display {% if score >= 7 %}high-score{% elif score >= 4 %}medium-score{% else %}low-score{% endif %}">
                    <h3>Overall Security Score</h3>
                    <h1 class="display-1">{{ "%.1f"|format(score) }}/10</h1>
                    <p class="mb-0">
                        {% if score >= 7 %}
                            <i class="bi bi-shield-check"></i> Good security practices detected
                        {% elif score >= 4 %}
                            <i class="bi bi-shield-exclamation"></i> Some security concerns identified
                        {% else %}
                            <i class="bi bi-shield-x"></i> Significant security issues detected
                        {% endif %}
                    </p>
                </div>
                
                <h3 class="main-section-title">Vulnerabilities Found ({{ vulnerabilities|length }})</h3>
                {% if vulnerabilities %}
                    {% set high_count = vulnerabilities|selectattr('severity', 'equalto', 'High')|list|length %}
                    {% set medium_count = vulnerabilities|selectattr('severity', 'equalto', 'Medium')|list|length %}
                    {% set low_count = vulnerabilities|selectattr('severity', 'equalto', 'Low')|list|length %}
                    
                    <div class="mb-4">
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
                    <h3 class="main-section-title">Security Report</h3>
                    <div id="report-content"></div>
                </div>
                
                <div class="mt-4">
                    <a href="/download-report/{{ filename }}" class="btn btn-success download-btn">
                        <i class="bi bi-file-earmark-text"></i> Download Report
                    </a>
                </div>
            </div>
            
            <div class="col-md-4">
                <div class="card mb-4">
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
                
                <h3 class="main-section-title">AI-Powered Recommendations</h3>
                
                {% if ai_recommendations and ai_recommendations|length > 1 %}
                    {% for rec in ai_recommendations %}
                        {% if loop.index > 1 and rec.strip() %}
                            <div class="recommendation-content">{{ rec }}</div>
                        {% endif %}
                    {% endfor %}
                {% else %}
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle"></i> AI recommendations unavailable or processing.
                    </div>
                {% endif %}
                
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
            <p class="mb-1">ACORN - AI Configuration Oversight for Router Networks</p>
            <p class="mb-0">&copy; 2025 - Developed by Brandon I.</p>
        </div>
    </footer>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const reportContent = document.getElementById('report-content');
            const report = `{{ report|safe }}`;
            reportContent.innerHTML = marked.parse(report);
            
            // Format AI recommendations
            const recommendations = document.querySelectorAll('.recommendation-content');
            recommendations.forEach(rec => {
                let content = rec.textContent;
                
                // Format numbered items and titles
                content = content.replace(/(\d+\.\s+\[[\w\s]+\]:)/g, '<strong>$1</strong>');
                
                // Format command sections
                content = content.replace(/- Command:(.*?)(?=-|$)/gs, function(match, p1) {
                    return '- <strong>Command:</strong><div class="command-box">' + p1.trim() + '</div>';
                });
                
                // Format benefit sections
                content = content.replace(/- Benefit:(.*?)(?=-|$)/gs, '- <strong>Benefit:</strong><span class="benefit-text">$1</span>');
                
                rec.innerHTML = content;
            });
        });
    </script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# Start the app if running directly
if __name__ == '__main__':
    print("Starting ACORN Web Interface...")
    print(f"Upload directory: {os.path.abspath(UPLOAD_FOLDER)}")
    print(f"Model path: {os.path.abspath(MODEL_PATH)}")
    print(f"OpenAI API Key configured: {'Yes' if OPENAI_API_KEY else 'No - Set OPENAI_API_KEY environment variable'}")
    print("Access the application at http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
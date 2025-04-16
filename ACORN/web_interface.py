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
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import tempfile
import time
import base64
from io import BytesIO

# Import ACORN modules
from ACORN.parser import parse_cisco_config
from ACORN.feature_extraction import extract_features
from rule_checker import check_telnet, check_password, check_acl, check_snmp
from generate_report import generate_report

# Constants
MODEL_PATH = "security_model.pkl"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'txt', 'conf'}
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
        return None

# Check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Process a configuration file
def process_config(file_path):
    """Process a configuration file and return analysis results."""
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
        # Convert features dict to DataFrame with one row
        feature_df = pd.DataFrame([features])
        
        # Get security score from model (probability of being secure)
        security_score = float(model.predict_proba(feature_df)[0][1] * 10)
    else:
        # If no model available, use simple heuristic based on vulnerability count an
#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
Interactive LLM Remediation Chat Interface

This module provides a chat-like interface for the LLM remediation advisor.
"""

import os
import sys
import json
import pickle
import pandas as pd
import requests
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
from tkinter.font import Font
from dotenv import load_dotenv
import threading

# Load environment variables from .env file
load_dotenv()

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

# Constants
MODEL_PATH = "security_model.pkl"
API_URL = "https://api.openai.com/v1/chat/completions"


class ScrollableFrame(ttk.Frame):
    """A scrollable frame widget"""
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        # Create a canvas and scrollbar
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Pack widgets
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Bind mousewheel to scroll
        self.bind_mousewheel()

    def bind_mousewheel(self):
        """Bind mousewheel to scroll"""
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def unbind_mousewheel(self):
        """Unbind mousewheel"""
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        """Scroll canvas on mousewheel"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")


class Message(ttk.Frame):
    """A chat message widget"""
    def __init__(self, parent, sender, text, is_user=False):
        super().__init__(parent)
        
        # Set color based on sender
        if is_user:
            bg_color = "#DCF8C6"  # Light green for user
            align_side = "right"
        else:
            bg_color = "#FFFFFF"  # White for bot
            align_side = "left"
        
        # Create message container
        message_frame = ttk.Frame(self)
        message_frame.pack(fill="x", padx=10, pady=5)
        
        # Message bubble
        bubble = ttk.Frame(message_frame, style="Bubble.TFrame")
        bubble.pack(side=align_side)
        
        # Sender label
        sender_label = ttk.Label(bubble, text=sender, style="Sender.TLabel")
        sender_label.pack(anchor="w", padx=10, pady=(5,0))
        
        # Message text (using Text widget for wrapping)
        text_widget = tk.Text(bubble, wrap="word", width=50, height=0, 
                              background=bg_color, borderwidth=0, padx=5)
        text_widget.insert("1.0", text)
        text_widget.configure(state="disabled")  # Make read-only
        text_widget.pack(padx=10, pady=5, fill="x")
        
        # Adjust text height to content
        line_count = int(text_widget.index('end-1c').split('.')[0])
        text_widget.configure(height=line_count)


class LLMChatApp:
    """Interactive LLM Remediation Chat Application"""
    def __init__(self, root):
        self.root = root
        self.root.title("ACORN - LLM Security Advisor")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Set styles
        self.style = ttk.Style()
        self.style.configure("Bubble.TFrame", background="#ECECEC", relief="raised", borderwidth=1)
        self.style.configure("Sender.TLabel", font=("Arial", 10, "bold"))
        
        # Create main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Top frame for file selection
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill="x", pady=10)
        
        ttk.Label(top_frame, text="Configuration File:").pack(side="left", padx=5)
        
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(top_frame, textvariable=self.file_path_var, width=40)
        file_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        browse_button = ttk.Button(top_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side="left", padx=5)
        
        analyze_button = ttk.Button(top_frame, text="Analyze", command=self.analyze_config)
        analyze_button.pack(side="left", padx=5)
        
        # Security score display
        self.score_frame = ttk.LabelFrame(main_frame, text="Security Analysis")
        self.score_frame.pack(fill="x", pady=10)
        
        self.score_var = tk.StringVar(value="No analysis performed")
        score_label = ttk.Label(self.score_frame, textvariable=self.score_var, font=("Arial", 12))
        score_label.pack(pady=10)
        
        self.vuln_count_var = tk.StringVar(value="")
        vuln_label = ttk.Label(self.score_frame, textvariable=self.vuln_count_var, font=("Arial", 10))
        vuln_label.pack(pady=5)
        
        # Chat area
        chat_frame = ttk.LabelFrame(main_frame, text="Security Advisor Chat")
        chat_frame.pack(fill="both", expand=True, pady=10)
        
        # Scrollable chat history
        self.chat_history = ScrollableFrame(chat_frame)
        self.chat_history.pack(fill="both", expand=True, pady=5)
        
        # Input area
        input_frame = ttk.Frame(chat_frame)
        input_frame.pack(fill="x", pady=5)
        
        self.user_input = tk.Text(input_frame, height=2, wrap="word")
        self.user_input.pack(side="left", fill="x", expand=True, padx=5)
        self.user_input.bind("<Return>", self.send_message)
        
        send_button = ttk.Button(input_frame, text="Send", command=self.send_message)
        send_button.pack(side="right", padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(side="bottom", fill="x")
        
        # Initialize variables
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.vulnerabilities = []
        self.config_sections = {}
        self.chat_history_messages = []
        
        # Check API key
        if not self.api_key:
            self.status_var.set("Warning: No OpenAI API key found. Set OPENAI_API_KEY in .env file.")
            
        # Welcome message
        self.add_message("ACORN Security Advisor", 
                        "Welcome to the ACORN Security Advisor. Select a configuration file and click 'Analyze' to begin.", 
                        is_user=False)

    def browse_file(self):
        """Open file browser to select configuration file"""
        file_path = filedialog.askopenfilename(
            title="Select Configuration File",
            filetypes=[("Configuration files", "*.conf *.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
    
    def analyze_config(self):
        """Analyze the selected configuration file"""
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            self.status_var.set("Error: Please select a valid configuration file")
            return
        
        self.status_var.set(f"Analyzing {os.path.basename(file_path)}...")
        
        # Use a thread to avoid freezing the UI
        threading.Thread(target=self._analyze_config_thread, args=(file_path,), daemon=True).start()
    
    def _analyze_config_thread(self, file_path):
        """Background thread for config analysis"""
        try:
            # Parse config into sections
            self.config_sections = parse_cisco_config(file_path)
            
            # Run rule-based checks
            self.vulnerabilities = []
            self.vulnerabilities.extend(check_telnet(self.config_sections))
            self.vulnerabilities.extend(check_password(self.config_sections))
            self.vulnerabilities.extend(check_acl(self.config_sections))
            self.vulnerabilities.extend(check_snmp(self.config_sections))
            
            # Extract features for ML model
            features = extract_features(self.config_sections)
            
            # Calculate security score
            security_score = self._calculate_security_score(features)
            
            # Update UI
            self.root.after(0, lambda: self._update_analysis_results(file_path, security_score))
            
        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
    
    def _calculate_security_score(self, features):
        """Calculate security score using model or heuristic"""
        try:
            # Try to load the model
            with open(MODEL_PATH, 'rb') as f:
                model = pickle.load(f)
            
            # Get expected feature names from model
            if hasattr(model, 'feature_names_in_'):
                expected_features = model.feature_names_in_
                # Create DataFrame with expected features
                feature_df = pd.DataFrame({feature: [features.get(feature, 0)] for feature in expected_features})
            else:
                # If model doesn't have feature_names_in_, just use all extracted features
                feature_df = pd.DataFrame([features])
            
            # Get security score from model
            security_score = model.predict_proba(feature_df)[0][1] * 10
            
        except:
            # Fallback to heuristic scoring
            high_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'High')
            med_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium')
            low_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'Low')
            
            # Simple weighted score (lower is better)
            vuln_score = (high_count * 3) + (med_count * 2) + low_count
            
            # Convert to 0-10 scale (higher is better)
            security_score = max(0, 10 - vuln_score)
        
        return security_score
    
    def _update_analysis_results(self, file_path, security_score):
        """Update UI with analysis results"""
        # Update security score
        self.score_var.set(f"Security Score: {security_score:.1f}/10")
        
        # Count vulnerabilities by severity
        high_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'High')
        med_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium')
        low_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'Low')
        
        # Update vulnerability count
        self.vuln_count_var.set(
            f"Vulnerabilities Found: {len(self.vulnerabilities)} " +
            f"(High: {high_count}, Medium: {med_count}, Low: {low_count})"
        )
        
        # Update status
        self.status_var.set(f"Analysis complete: {os.path.basename(file_path)}")
        
        # Add analysis message to chat
        if self.vulnerabilities:
            vuln_text = f"I found {len(self.vulnerabilities)} vulnerabilities in your configuration:\n\n"
            for i, vuln in enumerate(self.vulnerabilities[:3], 1):
                vuln_text += f"{i}. {vuln['severity']} - {vuln['description']}\n"
            
            if len(self.vulnerabilities) > 3:
                vuln_text += f"\n...and {len(self.vulnerabilities) - 3} more issues.\n"
                
            vuln_text += "\nHow would you like me to help? I can:"
            vuln_text += "\n- Provide detailed remediation steps"
            vuln_text += "\n- Explain specific vulnerabilities"
            vuln_text += "\n- Generate configuration fixes"
            
            self.add_message("ACORN Security Advisor", vuln_text, is_user=False)
        else:
            self.add_message("ACORN Security Advisor", 
                          "I didn't find any vulnerabilities in your configuration. Great job keeping your network secure!", 
                          is_user=False)
    
    def add_message(self, sender, text, is_user=False):
        """Add a message to the chat history"""
        message = Message(self.chat_history.scrollable_frame, sender, text, is_user)
        message.pack(fill="x", pady=5)
        
        # Store message in history
        self.chat_history_messages.append({"sender": sender, "text": text, "is_user": is_user})
        
        # Scroll to bottom
        self.chat_history.canvas.update_idletasks()
        self.chat_history.canvas.yview_moveto(1.0)
    
    def send_message(self, event=None):
        """Send user message and get LLM response"""
        # Get user message
        message = self.user_input.get("1.0", "end-1c").strip()
        if not message:
            return
        
        # Add user message to chat
        self.add_message("You", message, is_user=True)
        
        # Clear input
        self.user_input.delete("1.0", "end")
        
        # Return key should not add newline
        if event and event.keysym == "Return":
            return "break"
        
        # Check if analysis has been performed
        if not self.vulnerabilities and not self.config_sections:
            self.add_message("ACORN Security Advisor", 
                          "Please analyze a configuration file first.", 
                          is_user=False)
            return
        
        # Process with LLM in background
        self.status_var.set("Generating response...")
        threading.Thread(target=self._get_llm_response, args=(message,), daemon=True).start()
    
    def _get_llm_response(self, user_message):
        """Get response from LLM"""
        if not self.api_key:
            response = "I need an OpenAI API key to provide detailed remediation advice. Please set the OPENAI_API_KEY environment variable."
        else:
            try:
                # Format vulnerabilities for context
                vuln_text = ""
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    vuln_text += f"{i}. Severity: {vuln['severity']}, Issue: {vuln['description']}\n"
                
                # Format config sections for context
                config_text = ""
                for section, lines in self.config_sections.items():
                    if section == "global":
                        config_text += "\n".join(lines) + "\n\n"
                    else:
                        config_text += f"{section}\n" + "\n".join(f" {line}" for line in lines) + "\n!\n"
                
                # Truncate if too long
                if len(config_text) > 6000:
                    config_text = config_text[:6000] + "...[truncated]..."
                
                # Create conversation history
                messages = [
                    {"role": "system", "content": 
                     "You are a helpful Cisco network security advisor providing specific, actionable configuration advice. "
                     "Keep your responses concise, focused, and provide specific Cisco IOS commands to fix vulnerabilities. "
                     "Format your output neatly with clear sections and code formatting for commands."
                    }
                ]
                
                # Add context message
                context_message = f"""
                I'm analyzing a Cisco router configuration with the following vulnerabilities:
                
                {vuln_text}
                
                Here's the relevant parts of the current configuration:
                
                ```
                {config_text}
                ```
                
                The user is asking: "{user_message}"
                
                Provide a helpful response that addresses their question with specific Cisco IOS commands to fix the issues when appropriate.
                """
                
                messages.append({"role": "user", "content": context_message})
                
                # Make API request
                response = self._make_llm_request(messages)
                
            except Exception as e:
                response = f"I encountered an error while generating a response: {str(e)}"
        
        # Update UI with response
        self.root.after(0, lambda: self._update_with_response(response))
    
    def _make_llm_request(self, messages):
        """Make an API request to the LLM"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": "gpt-3.5-turbo",  # Use appropriate model
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 1000
        }
        
        response = requests.post(
            API_URL,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            return result["choices"][0]["message"]["content"]
        else:
            raise Exception(f"API request failed with status code {response.status_code}: {response.text}")
    
    def _update_with_response(self, response):
        """Update chat with LLM response"""
        self.add_message("ACORN Security Advisor", response, is_user=False)
        self.status_var.set("Ready")


def main():
    """Main function to start the application"""
    root = tk.Tk()
    app = LLMChatApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
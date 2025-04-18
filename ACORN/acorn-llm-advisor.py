#!/usr/bin/env python3
"""
ACORN LLM Advisor Integration
This module adds an AI advisor chatbot to the ACORN web interface for
intelligent network security analysis and recommendations.
"""

import os
import json
import requests
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename
import traceback
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
LLM_API_ENDPOINT = os.environ.get("LLM_API_ENDPOINT", "https://api.openai.com/v1/chat/completions")
LLM_API_KEY = os.getenv("OPENAI_API_KEY", "")
MODEL_NAME = os.environ.get("LLM_MODEL", "gpt-3.5-turbo")

class LLMAdvisor:
    """Class for handling LLM-based security advice"""
    
    def __init__(self, api_key=LLM_API_KEY, api_endpoint=LLM_API_ENDPOINT, model=MODEL_NAME):
        self.api_key = api_key
        self.api_endpoint = api_endpoint
        self.model = model
        self.conversation_history = {}  # Store conversation history by session ID
        
        # Check if API key is set
        if not self.api_key:
            logger.warning("LLM API key not set. Advisor functionality will be limited.")
    
    def get_security_advice(self, config_sections, vulnerabilities, session_id, user_query=None):
        """
        Get security advice from the LLM based on configuration and vulnerabilities
        
        Args:
            config_sections: Parsed network configuration
            vulnerabilities: List of vulnerabilities found
            session_id: Unique session identifier
            user_query: Optional specific user question
            
        Returns:
            dict: The LLM response with advice
        """
        if not self.api_key:
            return {
                "success": False,
                "message": "LLM API key not configured. Please set the OPENAI_API_KEY environment variable."
            }
        
        # Initialize conversation history for this session if it doesn't exist
        if session_id not in self.conversation_history:
            self.conversation_history[session_id] = []
        
        # Prepare the system prompt for the LLM
        system_prompt = """
        You are ACORN's Security Advisor, an expert in network device security, particularly for Cisco devices.
        Analyze the provided configuration and vulnerabilities to give specific, actionable security advice.
        Be concise but thorough. Focus on the most critical issues first.
        Provide advice that goes beyond the basic rule-based checks, looking for potential security weaknesses
        in the overall configuration. Include industry best practices and specific commands to implement
        recommendations when possible.
        """
        
        # Format vulnerabilities for the prompt
        vuln_text = "Vulnerabilities found:\n"
        for v in vulnerabilities:
            vuln_text += f"- {v['severity']}: {v['description']} (Recommendation: {v['recommendation']})\n"
        
        # Create the user message content
        if user_query:
            user_message = f"""
            Configuration sections:
            {json.dumps(config_sections, indent=2)}
            
            {vuln_text}
            
            User question: {user_query}
            
            Please provide your expert analysis and recommendations.
            """
        else:
            user_message = f"""
            Configuration sections:
            {json.dumps(config_sections, indent=2)}
            
            {vuln_text}
            
            Please provide your expert analysis and recommendations.
            """
        
        # Prepare the messages array including conversation history
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(self.conversation_history[session_id])
        messages.append({"role": "user", "content": user_message})
        
        # Prepare the API request for OpenAI
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        data = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 2000,
            "temperature": 0.7
        }
        
        try:
            # Make the API request
            response = requests.post(
                self.api_endpoint,
                headers=headers,
                json=data
            )
            
            # Parse the response
            if response.status_code == 200:
                result = response.json()
                
                # Extract the assistant's message from OpenAI response
                assistant_message = result["choices"][0]["message"]["content"]
                
                # Update conversation history
                self.conversation_history[session_id].append({"role": "user", "content": user_message})
                self.conversation_history[session_id].append({"role": "assistant", "content": assistant_message})
                
                # Keep history limited to last 10 messages
                if len(self.conversation_history[session_id]) > 10:
                    self.conversation_history[session_id] = self.conversation_history[session_id][-10:]
                
                return {
                    "success": True,
                    "message": assistant_message,
                    "conversation_id": session_id
                }
            else:
                logger.error(f"LLM API error: {response.status_code} - {response.text}")
                return {
                    "success": False,
                    "message": f"Error from LLM API: {response.status_code} - {response.text}"
                }
        
        except Exception as e:
            logger.error(f"Exception in LLM request: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "success": False,
                "message": f"Error accessing LLM API: {str(e)}"
            }
    
    def reset_conversation(self, session_id):
        """Reset the conversation history for a given session"""
        if session_id in self.conversation_history:
            self.conversation_history[session_id] = []
        return {"success": True, "message": "Conversation reset"}


# Create LLM advisor instance
llm_advisor = LLMAdvisor()

# Routes to add to the main Flask app
def register_advisor_routes(app):
    """Register the LLM advisor routes with the main Flask app"""
    
    @app.route('/api/advisor', methods=['POST'])
    def get_advice():
        """Endpoint to get security advice from the LLM"""
        try:
            data = request.json
            
            # Validate required fields
            if 'config_sections' not in data:
                return jsonify({"success": False, "message": "Missing required field: config_sections"}), 400
            
            if 'vulnerabilities' not in data:
                return jsonify({"success": False, "message": "Missing required field: vulnerabilities"}), 400
            
            # Get session ID or generate one
            session_id = data.get('session_id', request.remote_addr)
            
            # Get optional user query
            user_query = data.get('user_query', None)
            
            # Get advice from LLM
            result = llm_advisor.get_security_advice(
                data['config_sections'],
                data['vulnerabilities'],
                session_id,
                user_query
            )
            
            return jsonify(result)
        
        except Exception as e:
            logger.error(f"Error in /api/advisor: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500
    
    @app.route('/api/advisor/reset', methods=['POST'])
    def reset_advice_conversation():
        """Endpoint to reset the conversation with the LLM advisor"""
        try:
            data = request.json
            session_id = data.get('session_id', request.remote_addr)
            result = llm_advisor.reset_conversation(session_id)
            return jsonify(result)
        
        except Exception as e:
            logger.error(f"Error in /api/advisor/reset: {str(e)}")
            return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

# Export the function to register routes
__all__ = ['register_advisor_routes']
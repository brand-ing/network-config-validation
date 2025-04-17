#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
Machine Learning Pipeline (Fixed Version)

This script provides an ML pipeline for training, evaluating,
and fine-tuning router security classification models.
"""

import os
import pickle
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
import seaborn as sns

# Constants
MODEL_PATH = "security_model.pkl"
RESULTS_DIR = "model_evaluation"

def load_dataset(csv_path):
    """
    Load and prepare the dataset for training.
    
    Args:
        csv_path: Path to the features CSV file
        
    Returns:
        X_train, X_test, y_train, y_test, feature_cols
    """
    print(f"Loading dataset from {csv_path}...")
    
    # Check if file exists
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset file not found: {csv_path}")
    
    # Load the data with error handling
    try:
        df = pd.read_csv(csv_path)
        print(f"DataFrame shape: {df.shape}")
        print(f"DataFrame columns: {df.columns.tolist()}")
        
        # Check if DataFrame is empty
        if df.empty:
            raise ValueError("Dataset is empty")
        
        # Check if 'secure' column exists
        if 'secure' not in df.columns:
            raise ValueError("Dataset must contain a 'secure' column with labels")
        
        # Drop non-feature columns
        non_feature_cols = ['secure']
        if 'filename' in df.columns:
            non_feature_cols.append('filename')
        
        feature_cols = [col for col in df.columns if col not in non_feature_cols]
        
        # Check if we have any features
        if not feature_cols:
            raise ValueError("No feature columns found in dataset")
        
        print(f"Found {len(feature_cols)} feature columns: {feature_cols}")
        
        # Split features and target
        X = df[feature_cols]
        y = df['secure']
        
        # Check for NaN values and replace with 0
        if X.isna().any().any():
            print("Warning: NaN values found in features, replacing with 0")
            X = X.fillna(0)
        
        # Split into training and test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"Dataset loaded: {len(X_train)} training samples, {len(X_test)} test samples")
        
        return X_train, X_test, y_train, y_test, feature_cols
    
    except Exception as e:
        print(f"Error loading dataset: {e}")
        raise

def train_model(X_train, y_train):
    """
    Train a RandomForestClassifier model.
    
    Args:
        X_train: Training features
        y_train: Training labels
        
    Returns:
        Trained model
    """
    print("Training Random Forest model...")
    
    # Create and train the model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42
    )
    
    model.fit(X_train, y_train)
    
    return model

def evaluate_model(model, X_test, y_test, feature_names=None):
    """
    Evaluate the model's performance on test data.
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: Test labels
        feature_names: List of feature names
        
    Returns:
        Dictionary of evaluation metrics
    """
    print("Evaluating model performance...")
    
    # Create directory for results if it doesn't exist
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    # Print results
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    # Create classification report
    class_report = classification_report(y_test, y_pred)
    print("\nClassification Report:")
    print(class_report)
    
    # Create confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)
    
    # Plot and save confusion matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Insecure', 'Secure'],
                yticklabels=['Insecure', 'Secure'])
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, 'confusion_matrix.png'))
    plt.close()
    
    # Plot and save ROC curve
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, 'roc_curve.png'))
    plt.close()
    
    # Plot feature importance if available and feature names provided
    if hasattr(model, 'feature_importances_') and feature_names is not None:
        # Create DataFrame for feature importance
        feature_imp = pd.DataFrame({
            'Feature': feature_names,
            'Importance': model.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        # Plot feature importance
        plt.figure(figsize=(10, 8))
        sns.barplot(x='Importance', y='Feature', data=feature_imp)
        plt.title('Feature Importance')
        plt.tight_layout()
        plt.savefig(os.path.join(RESULTS_DIR, 'feature_importance.png'))
        plt.close()
        
        # Save feature importance to CSV
        feature_imp.to_csv(os.path.join(RESULTS_DIR, 'feature_importance.csv'), index=False)
    
    # Return metrics
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc if 'roc_auc' in locals() else None
    }

def save_model(model, output_path=MODEL_PATH):
    """
    Save the trained model to disk.
    
    Args:
        model: Trained model
        output_path: Path to save the model to
    """
    print(f"Saving model to {output_path}...")
    
    with open(output_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"Model saved to {output_path}")

def main():
    """Main entry point for ML pipeline."""
    import argparse
    
    parser = argparse.ArgumentParser(description="ACORN Machine Learning Pipeline")
    parser.add_argument("--data", default="config_features.csv", help="Path to the features CSV file")
    parser.add_argument("--output", default=MODEL_PATH, help="Output path for the trained model")
    
    args = parser.parse_args()
    
    # Load dataset
    try:
        X_train, X_test, y_train, y_test, feature_names = load_dataset(args.data)
        
        # Train model
        model = train_model(X_train, y_train)
        
        # Evaluate model
        metrics = evaluate_model(model, X_test, y_test, feature_names)
        
        # Save model
        save_model(model, args.output)
        
        # Print summary
        print("\nTraining and evaluation complete!")
        print(f"Evaluation metrics saved to {RESULTS_DIR}/")
        print(f"Model saved to {args.output}")
    
    except Exception as e:
        print(f"ERROR: {e}")
        print("\nIf you're having trouble with your dataset, try generating a test dataset with:")
        print("python generate_test_dataset.py --output test_features.csv")
        print("Then run this script with: python ml_pipeline.py --data test_features.csv")

if __name__ == "__main__":
    main()
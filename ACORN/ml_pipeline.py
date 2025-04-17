#!/usr/bin/env python3
"""
ACORN: AI Configuration Oversight for Router Networks
Machine Learning Pipeline

This script provides an advanced ML pipeline for training, evaluating,
and fine-tuning router security classification models.
"""

import os
import pickle
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import SelectFromModel
import seaborn as sns


# Constants
MODEL_PATH = "security_model.pkl"
RESULTS_DIR = "model_evaluation"

def load_dataset(csv_path):
    """
    Load and prepare the dataset for training with improved error handling.
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
        
        # Check for NaN values
        nan_count = df.isna().sum().sum()
        if nan_count > 0:
            print(f"Warning: Dataset contains {nan_count} NaN values")
        
        # Print value counts for the target
        print(f"Target distribution:\n{df['secure'].value_counts()}")
        
        # Drop non-feature columns
        feature_cols = [col for col in df.columns if col not in ['secure', 'filename']]
        
        if not feature_cols:
            raise ValueError("No feature columns found in dataset")
        
        # Split features and target
        X = df[feature_cols]
        y = df['secure']
        
        # Split into training and test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"Dataset loaded: {len(X_train)} training samples, {len(X_test)} test samples")
        print(f"Features: {', '.join(feature_cols)}")
        
        return X_train, X_test, y_train, y_test, feature_cols
    
    except Exception as e:
        print(f"Error loading dataset: {e}")
        print("Contents of the dataset file:")
        with open(csv_path, 'r') as f:
            print(f.read(1000))  # Print first 1000 chars for debugging
        raise


def train_basic_model(X_train, y_train):
    """
    Train a basic RandomForestClassifier model.
    
    Args:
        X_train: Training features
        y_train: Training labels
        
    Returns:
        Trained model
    """
    print("Training basic Random Forest model...")
    
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

def train_advanced_model(X_train, y_train):
    """
    Train an advanced model with hyperparameter tuning.
    
    Args:
        X_train: Training features
        y_train: Training labels
        
    Returns:
        Trained model
    """
    print("Training advanced model with hyperparameter tuning...")
    
    # Create a pipeline with preprocessing and model
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(random_state=42))
    ])
    
    # Define hyperparameter grid for tuning
    param_grid = {
        'classifier__n_estimators': [50, 100, 200],
        'classifier__max_depth': [None, 10, 20, 30],
        'classifier__min_samples_split': [2, 5, 10],
        'classifier__min_samples_leaf': [1, 2, 4]
    }
    
    # Grid search for optimal hyperparameters
    grid_search = GridSearchCV(
        pipeline, param_grid, cv=5, scoring='f1', n_jobs=-1
    )
    
    # Train the model
    grid_search.fit(X_train, y_train)
    
    # Print the best parameters
    print(f"Best parameters: {grid_search.best_params_}")
    print(f"Best CV score: {grid_search.best_score_:.4f}")
    
    # Return the best model
    return grid_search.best_estimator_

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
    
    # Create directory for results if it doesn't exist
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
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
    
    # Plot feature importance if available and feature names provided
    if hasattr(model, 'feature_importances_') and feature_names is not None:
        # If using a pipeline, extract the classifier
        if hasattr(model, 'named_steps') and 'classifier' in model.named_steps:
            importances = model.named_steps['classifier'].feature_importances_
        else:
            importances = model.feature_importances_
        
        # Create DataFrame for feature importance
        feature_imp = pd.DataFrame({
            'Feature': feature_names,
            'Importance': importances
        }).sort_values('Importance', ascending=False)
        
        # Plot feature importance
        plt.figure(figsize=(10, 8))
        sns.barplot(x='Importance', y='Feature', data=feature_imp)
        plt.title('Feature Importance')
        plt.tight_layout()
        plt.savefig(os.path.join(RESULTS_DIR, 'feature_importance.png'))
        
        # Save feature importance to CSV
        feature_imp.to_csv(os.path.join(RESULTS_DIR, 'feature_importance.csv'), index=False)
    
    # Return metrics
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc
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

def generate_security_levels(model, X_test, feature_names):
    """
    Generate a mapping of feature changes to security level impact.
    
    Args:
        model: Trained model
        X_test: Test features
        feature_names: List of feature names
        
    Returns:
        DataFrame with feature impact data
    """
    print("Generating security impact analysis...")
    
    # Create a DataFrame to track feature impacts
    impact_data = []
    
    # Get baseline predictions for all test samples
    baseline_probs = model.predict_proba(X_test)[:, 1]
    
    # Check impact of changing each feature
    for i, feature in enumerate(feature_names):
        # Deep copy the test data
        X_modified = X_test.copy()
        
        # For binary features (0/1)
        if set(X_test.iloc[:, i].unique()).issubset({0, 1}):
            # Set feature to 1 (secure value)
            X_modified.iloc[:, i] = 1
            
            # Get new predictions
            new_probs = model.predict_proba(X_modified)[:, 1]
            
            # Calculate average impact
            avg_impact = np.mean(new_probs - baseline_probs)
            
            impact_data.append({
                'Feature': feature,
                'Average Impact': avg_impact,
                'Type': 'Binary'
            })
        else:
            # For continuous features, increase by 1 unit
            X_modified.iloc[:, i] = X_test.iloc[:, i] + 1
            
            # Get new predictions
            new_probs = model.predict_proba(X_modified)[:, 1]
            
            # Calculate average impact
            avg_impact = np.mean(new_probs - baseline_probs)
            
            impact_data.append({
                'Feature': feature,
                'Average Impact': avg_impact,
                'Type': 'Continuous'
            })
    
    # Convert to DataFrame
    impact_df = pd.DataFrame(impact_data)
    
    # Sort by absolute impact
    impact_df = impact_df.reindex(impact_df['Average Impact'].abs().sort_values(ascending=False).index)
    
    # Save to CSV
    impact_df.to_csv(os.path.join(RESULTS_DIR, 'security_impacts.csv'), index=False)
    
    # Plot feature impacts
    plt.figure(figsize=(12, 10))
    colors = ['g' if x > 0 else 'r' for x in impact_df['Average Impact']]
    sns.barplot(x='Average Impact', y='Feature', data=impact_df, palette=colors)
    plt.title('Feature Impact on Security Score')
    plt.axvline(x=0, color='black', linestyle='-')
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, 'security_impacts.png'))
    
    return impact_df

def main():
    """Main entry point for ML pipeline."""
    import argparse
    
    parser = argparse.ArgumentParser(description="ACORN Machine Learning Pipeline")
    parser.add_argument("--data", default="config_features.csv", help="Path to the features CSV file")
    parser.add_argument("--advanced", action="store_true", help="Use advanced model with hyperparameter tuning")
    parser.add_argument("--output", default=MODEL_PATH, help="Output path for the trained model")
    
    args = parser.parse_args()
    
    # Load dataset
    X_train, X_test, y_train, y_test, feature_names = load_dataset(args.data)
    
    # Train model
    if args.advanced:
        model = train_advanced_model(X_train, y_train)
    else:
        model = train_basic_model(X_train, y_train)
    
    # Evaluate model
    metrics = evaluate_model(model, X_test, y_test, feature_names)
    
    # Generate security impact analysis
    impact_analysis = generate_security_levels(model, X_test, feature_names)
    
    # Save model
    save_model(model, args.output)
    
    # Print summary
    print("\nTraining and evaluation complete!")
    print(f"Evaluation metrics saved to {RESULTS_DIR}/")
    print(f"Model saved to {args.output}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CHOMBEZA - Machine Learning False Positive Reducer
Uses ML to classify findings as true/false positives
"""

import os
import json
import pickle
import logging
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("CHOMBEZA.ML_FPReducer")

# Try to import ML libraries (optional)
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logger.warning("scikit-learn not installed. ML false positive reduction disabled.")

class MLFalsePositiveReducer:
    """
    Machine Learning-based false positive reduction
    Learns from user feedback to improve detection accuracy
    """
    
    def __init__(self, model_dir: str = "ml_models"):
        self.model_dir = model_dir
        self.model = None
        self.vectorizer = None
        self.training_data = []
        self.labels = []
        self.is_trained = False
        self.feature_extractors = self._init_feature_extractors()
        
        # Create model directory
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Try to load existing model
        self.load_model()
    
    def _init_feature_extractors(self) -> List:
        """Initialize feature extraction functions"""
        return [
            self._extract_response_length,
            self._extract_status_code,
            self._extract_payload_position,
            self._extract_error_patterns,
            self._extract_confidence_score,
            self._extract_vuln_type,
            self._extract_severity,
            self._extract_payload_complexity,
            self._extract_response_time,
            self._extract_reflection_context
        ]
    
    def _extract_response_length(self, finding: Dict) -> float:
        """Extract response length feature"""
        response = finding.get('request_response', '')
        return len(response) / 10000  # Normalize
    
    def _extract_status_code(self, finding: Dict) -> float:
        """Extract HTTP status code feature"""
        # One-hot encode common status codes
        status = finding.get('status_code', 200)
        if status == 200:
            return 1.0
        elif status == 404:
            return 0.8
        elif status == 500:
            return 0.6
        elif status >= 400:
            return 0.4
        else:
            return 0.2
    
    def _extract_payload_position(self, finding: Dict) -> float:
        """Extract where payload was found in response"""
        evidence = finding.get('evidence', '')
        if 'reflected in response' in evidence.lower():
            return 1.0
        elif 'error message' in evidence.lower():
            return 0.7
        elif 'headers' in evidence.lower():
            return 0.5
        else:
            return 0.3
    
    def _extract_error_patterns(self, finding: Dict) -> float:
        """Extract error pattern indicators"""
        evidence = finding.get('evidence', '').lower()
        error_indicators = [
            'sql', 'syntax', 'mysql', 'odbc', 'ora-',
            'warning', 'fatal', 'exception', 'stack trace'
        ]
        
        score = 0
        for indicator in error_indicators:
            if indicator in evidence:
                score += 1
        
        return min(score / len(error_indicators), 1.0)
    
    def _extract_confidence_score(self, finding: Dict) -> float:
        """Extract confidence score feature"""
        return finding.get('confidence', 50) / 100.0
    
    def _extract_vuln_type(self, finding: Dict) -> float:
        """Extract vulnerability type feature"""
        vuln_type = finding.get('name', '').lower()
        
        # Map vulnerability types to numeric values
        type_map = {
            'xss': 1.0,
            'sqli': 0.9,
            'rce': 0.95,
            'lfi': 0.85,
            'ssti': 0.8,
            'xxe': 0.75,
            'ssrf': 0.7,
            'idor': 0.65,
            'open_redirect': 0.6,
            'cors': 0.55,
            'jwt': 0.5,
            'graphql': 0.45,
            'nosqli': 0.4,
            'ldapi': 0.35
        }
        
        for key, value in type_map.items():
            if key in vuln_type:
                return value
        
        return 0.3  # Default
    
    def _extract_severity(self, finding: Dict) -> float:
        """Extract severity feature"""
        severity = finding.get('severity', 'info').lower()
        severity_map = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'info': 0.2
        }
        return severity_map.get(severity, 0.2)
    
    def _extract_payload_complexity(self, finding: Dict) -> float:
        """Extract payload complexity feature"""
        evidence = finding.get('evidence', '')
        
        # Count special characters and length
        special_chars = sum(1 for c in evidence if not c.isalnum() and not c.isspace())
        length = len(evidence)
        
        complexity = (special_chars / max(length, 1)) * (min(length, 100) / 100)
        return min(complexity, 1.0)
    
    def _extract_response_time(self, finding: Dict) -> float:
        """Extract response time feature"""
        # Parse response time from evidence if available
        evidence = finding.get('evidence', '')
        import re
        
        time_match = re.search(r'(\d+\.?\d*)\s*(?:ms|seconds?)', evidence, re.I)
        if time_match:
            response_time = float(time_match.group(1))
            # Normalize to 0-1 (assuming 10s max)
            return min(response_time / 10.0, 1.0)
        
        return 0.5  # Default
    
    def _extract_reflection_context(self, finding: Dict) -> float:
        """Extract where payload was reflected"""
        evidence = finding.get('evidence', '').lower()
        
        if 'script' in evidence and 'context' in evidence:
            return 1.0  # Script context is dangerous
        elif 'attribute' in evidence:
            return 0.8
        elif 'html' in evidence:
            return 0.6
        elif 'comment' in evidence:
            return 0.3
        else:
            return 0.4
    
    def extract_features(self, finding: Dict) -> np.ndarray:
        """Extract feature vector from a finding"""
        features = []
        for extractor in self.feature_extractors:
            try:
                features.append(extractor(finding))
            except Exception as e:
                logger.debug(f"Feature extraction failed: {e}")
                features.append(0.5)  # Default value
        
        return np.array(features)
    
    def add_training_sample(self, finding: Dict, is_true_positive: bool):
        """Add a training sample with user feedback"""
        features = self.extract_features(finding)
        self.training_data.append(features)
        self.labels.append(1 if is_true_positive else 0)
        
        # Auto-train if we have enough samples
        if len(self.training_data) >= 10 and not self.is_trained:
            self.train()
    
    def train(self) -> bool:
        """Train the ML model"""
        if not HAS_SKLEARN:
            logger.warning("scikit-learn not available for training")
            return False
        
        if len(self.training_data) < 10:
            logger.warning(f"Not enough training samples: {len(self.training_data)} < 10")
            return False
        
        try:
            X = np.array(self.training_data)
            y = np.array(self.labels)
            
            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.model.fit(X, y)
            
            # Evaluate
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            self.model.fit(X_train, y_train)
            y_pred = self.model.predict(X_test)
            
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            
            self.is_trained = True
            
            logger.info(f"Model trained - Accuracy: {accuracy:.2f}, Precision: {precision:.2f}, Recall: {recall:.2f}")
            
            # Save model
            self.save_model()
            
            return True
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return False
    
    def predict(self, finding: Dict) -> Tuple[float, str]:
        """
        Predict if finding is a true positive
        
        Returns:
            Tuple of (confidence, classification)
        """
        if not self.is_trained or not self.model:
            return 0.5, "unknown"
        
        try:
            features = self.extract_features(finding).reshape(1, -1)
            probability = self.model.predict_proba(features)[0][1]  # Probability of true positive
            
            if probability >= 0.7:
                classification = "true_positive"
            elif probability >= 0.4:
                classification = "uncertain"
            else:
                classification = "false_positive"
            
            return probability, classification
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return 0.5, "unknown"
    
    def save_model(self):
        """Save trained model to disk"""
        if not self.is_trained:
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_path = os.path.join(self.model_dir, f"model_{timestamp}.pkl")
            
            with open(model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'training_data': self.training_data,
                    'labels': self.labels,
                    'timestamp': timestamp
                }, f)
            
            logger.info(f"Model saved to {model_path}")
            
            # Keep only latest 5 models
            self._cleanup_old_models()
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def load_model(self, model_path: Optional[str] = None):
        """Load trained model from disk"""
        if not HAS_SKLEARN:
            return
        
        try:
            if model_path and os.path.exists(model_path):
                path = model_path
            else:
                # Find latest model
                models = sorted([
                    f for f in os.listdir(self.model_dir) 
                    if f.startswith('model_') and f.endswith('.pkl')
                ])
                if not models:
                    return
                path = os.path.join(self.model_dir, models[-1])
            
            with open(path, 'rb') as f:
                data = pickle.load(f)
            
            self.model = data['model']
            self.training_data = data['training_data']
            self.labels = data['labels']
            self.is_trained = True
            
            logger.info(f"Model loaded from {path}")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    def _cleanup_old_models(self, keep: int = 5):
        """Keep only the most recent models"""
        models = sorted([
            f for f in os.listdir(self.model_dir) 
            if f.startswith('model_') and f.endswith('.pkl')
        ])
        
        for old_model in models[:-keep]:
            try:
                os.remove(os.path.join(self.model_dir, old_model))
                logger.debug(f"Removed old model: {old_model}")
            except:
                pass
    
    def get_stats(self) -> Dict:
        """Get model statistics"""
        stats = {
            "is_trained": self.is_trained,
            "training_samples": len(self.training_data),
            "positive_samples": sum(1 for l in self.labels if l == 1),
            "negative_samples": sum(1 for l in self.labels if l == 0)
        }
        
        if self.is_trained and self.model:
            stats["feature_importance"] = {
                f"feature_{i}": importance 
                for i, importance in enumerate(self.model.feature_importances_)
            }
        
        return stats

# Global instance
_ml_reducer = None

def get_ml_reducer() -> MLFalsePositiveReducer:
    """Get or create global ML reducer instance"""
    global _ml_reducer
    if _ml_reducer is None:
        _ml_reducer = MLFalsePositiveReducer()
    return _ml_reducer
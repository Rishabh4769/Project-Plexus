"""
model_loader.py
================
Responsible for loading the trained XGBoost model and scaling parameters
to perform thread-safe real-time predictions.
"""

import os
import json
import logging
from pathlib import Path
import joblib
import pandas as pd

# Setup logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("model_loader")

class NIDSModelLoader:
    def __init__(self):
        # Locate project paths
        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.artifacts_dir = self.base_dir / "ml" / "artifacts"
        
        self.model_path = self.artifacts_dir / "model.joblib"
        self.scaler_path = self.artifacts_dir / "scaler.joblib"
        self.spec_path = self.artifacts_dir / "feature_spec.json"
        
        self.model = None
        self.scaler = None
        self.selected_features = []
        
        self.load_artifacts()

    def load_artifacts(self):
        """Loads XGBoost classifier, StandardScaler, and the selected feature spec."""
        try:
            if not self.model_path.exists() or not self.scaler_path.exists() or not self.spec_path.exists():
                log.error("NIDS Model artifacts are missing! Make sure to run the training pipeline first.")
                return

            log.info("Loading NIDS XGBoost classifier...")
            self.model = joblib.load(self.model_path)
            
            log.info("Loading feature scaler...")
            self.scaler = joblib.load(self.scaler_path)
            
            log.info("Loading feature specifications...")
            with open(self.spec_path, "r") as f:
                spec = json.load(f)
                self.selected_features = spec["selected_features"]
                
            log.info(f"NIDS Model loader initialized successfully with {len(self.selected_features)} features.")
        except Exception as e:
            log.exception(f"Failed to load NIDS model artifacts: {e}")

    def predict(self, features_dict: dict) -> tuple[bool, float]:
        """
        Takes a raw feature dictionary from the flow aggregator, scales the values,
        and uses the loaded XGBoost model to perform a classification.
        Returns:
            (is_attack: bool, probability: float)
        """
        if self.model is None or self.scaler is None:
            # Fallback if model failed to load
            return False, 0.0

        try:
            # Order the features precisely matching the feature spec
            vector = [features_dict.get(feat, 0.0) for feat in self.selected_features]
            
            # Format as DataFrame to prevent warnings/errors on feature names if scaler uses them
            df_vector = pd.DataFrame([vector], columns=self.selected_features)
            
            # Scale the features
            scaled_vector = self.scaler.transform(df_vector)
            
            # Predict
            prob = float(self.model.predict_proba(scaled_vector)[0][1])
            is_attack = bool(self.model.predict(scaled_vector)[0] == 1)
            
            return is_attack, prob
        except Exception as e:
            log.error(f"Error during flow classification: {e}")
            return False, 0.0

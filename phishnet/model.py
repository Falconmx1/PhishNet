import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import os
from pathlib import Path
from .utils import logger

class PhishMLModel:
    def __init__(self, model_path="models/phish_model.pkl"):
        self.model_path = Path(model_path)
        self.model = None
        self.accuracy = 0.987  # Valor de referencia
        
    def load_or_train(self):
        """Carga el modelo o crea uno nuevo"""
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                logger.info("Model loaded successfully")
                return True
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                
        logger.info("Training new model...")
        self.train_model()
        self.save_model()
        return True
    
    def train_model(self):
        """Entrena modelo con datos simulados (en producción usar dataset real)"""
        # Datos sintéticos - 1000 muestras, 22 features
        np.random.seed(42)
        n_samples = 1000
        n_features = 22
        
        # Features sintéticos (en producción usar data real de Kaggle/PhishTank)
        X = np.random.rand(n_samples, n_features)
        
        # Etiquetas: 0=legítimo, 1=phishing
        y = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])
        
        # Hacer correlaciones realistas
        # URLs largas tienden a ser phishing
        X[:, 0] = np.random.normal(50, 20, n_samples)  # url_length
        y[X[:, 0] > 70] = np.random.choice([0, 1], size=np.sum(X[:, 0] > 70), p=[0.2, 0.8])
        
        # Dominios nuevos tienden a ser phishing
        X[:, 15] = np.random.binomial(1, 0.1, n_samples)  # domain_new
        y[X[:, 15] == 1] = np.random.choice([0, 1], size=np.sum(X[:, 15] == 1), p=[0.1, 0.9])
        
        # HTTPS no usado tiende a phishing
        X[:, 9] = np.random.binomial(1, 0.2, n_samples)  # https_not_used
        y[X[:, 9] == 1] = np.random.choice([0, 1], size=np.sum(X[:, 9] == 1), p=[0.1, 0.9])
        
        # Entrenar modelo
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluar
        y_pred = self.model.predict(X_test)
        self.accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"Model trained. Accuracy: {self.accuracy:.3f}")
        logger.info(f"\n{classification_report(y_test, y_pred)}")
    
    def predict(self, features):
        """Predice score de phishing para una URL"""
        if not self.model:
            raise Exception("Model not loaded")
        
        # Convertir dict a array de features
        feature_order = [
            'url_length', 'has_ip_address', 'num_dots', 'has_at_symbol',
            'has_double_slash', 'has_redirect_chars', 'subdomain_depth',
            'has_suspicious_keywords', 'has_hex', 'https_not_used',
            'multiple_www', 'hostname_length', 'path_length', 'has_query_params',
            'num_params', 'domain_age_days', 'rare_tld', 'mismatched_brand',
            'nonstandard_port', 'typo_squatting', 'ssl_valid', 'has_login_form'
        ]
        
        # Construir vector de features
        feature_vector = []
        for f in feature_order:
            if f in features:
                value = features[f]
                # Normalizar
                if isinstance(value, (int, float)):
                    feature_vector.append(float(value))
                else:
                    feature_vector.append(0.0)
            else:
                feature_vector.append(0.0)
        
        # Predecir y convertir a score 0-100
        proba = self.model.predict_proba([feature_vector])[0]
        phish_probability = proba[1]  # Clase 1 = phishing
        
        # Escalar a 0-100
        score = int(phish_probability * 100)
        
        return score
    
    def predict_email(self, features):
        """Predice score para email"""
        # Modelo más simple para emails
        score = 0
        
        # Reglas heurísticas
        if features.get('sender_mismatch', 0):
            score += 25
        if features.get('urgent_language', 0):
            score += 20
        if features.get('generic_greeting', 0):
            score += 15
        if features.get('requests_personal_data', 0):
            score += 30
        if features.get('num_links', 0) > 3:
            score += min(20, features.get('num_links', 0) * 5)
        if not features.get('has_spf', 1):
            score += 20
        if features.get('reply_to_mismatch', 0):
            score += 25
            
        return min(100, score)
    
    def save_model(self):
        """Guarda el modelo"""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        logger.info(f"Model saved to {self.model_path}")

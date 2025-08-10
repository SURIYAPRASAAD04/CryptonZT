import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import (classification_report, confusion_matrix, 
                            roc_auc_score, precision_recall_curve, 
                            average_precision_score, accuracy_score,
                            f1_score, precision_score, recall_score)
from sklearn.preprocessing import StandardScaler
from joblib import dump, load
import matplotlib.pyplot as plt
import seaborn as sns
from imblearn.over_sampling import SMOTE
from sklearn.calibration import CalibratedClassifierCV
from time import time

class AnomalyDetector:
    def __init__(self):
        self.models = {
            'encryption': None,
            'decryption': None
        }
        self.scalers = {
            'encryption': StandardScaler(),
            'decryption': StandardScaler()
        }
        self.features = {
            'encryption': ['api_calls', 'memory', 'cpu', 'time_ratio', 'cpu_memory_ratio',
                         'payload_entropy', 'rolling_cpu_10s', 'fragments'],
            'decryption': ['time_ms', 'fragment_ratio', 'cpu', 'entropy_product',
                         'rolling_cpu_10s', 'memory', 'geo_entropy']
        }
        self.thresholds = {
            'encryption': -0.35,
            'decryption': -0.4
        }
        self.training_times = {
            'encryption': 0,
            'decryption': 0
        }
    
    def load_and_preprocess(self, filepath):
        df = pd.read_csv(filepath)
        
        
        df['time_ratio'] = df.groupby('layer')['time_ms'].transform(lambda x: x / x.median())
        df['cpu_memory_ratio'] = df['cpu'] / (df['memory'] + 1e-6)
        df['entropy_product'] = df['geo_entropy'] * df['payload_entropy']
        df['fragment_ratio'] = df['fragments'] / df.groupby('phase')['fragments'].transform('max')
        
        
        enc_data = df[df['phase'] == 'encryption'].copy()
        dec_data = df[df['phase'] == 'decryption'].copy()
        
        return enc_data, dec_data
    
    def train_models(self, enc_data, dec_data):
        print("Training Encryption Model...")
        X_enc = enc_data[self.features['encryption']]
        y_enc = enc_data['is_anomaly']
        
      
        X_enc_scaled = self.scalers['encryption'].fit_transform(X_enc)
        
       
        start_time = time()
        enc_model = IsolationForest(
            n_estimators=200,
            max_samples=512,
            contamination=0.07,
            random_state=42,
            verbose=1
        )
        enc_model.fit(X_enc_scaled)
        self.training_times['encryption'] = time() - start_time
        
       
        if y_enc.sum() > 0:  
            rf_enc = RandomForestClassifier(n_estimators=100, random_state=42)
            rf_enc.fit(X_enc_scaled, y_enc)
            self.models['encryption'] = (enc_model, rf_enc)
        else:
            self.models['encryption'] = (enc_model, None)
        
        print("\nTraining Decryption Model...")
        X_dec = dec_data[self.features['decryption']]
        y_dec = dec_data['is_anomaly']
               
        X_dec_scaled = self.scalers['decryption'].fit_transform(X_dec)
        
       
        start_time = time()
        dec_model = IsolationForest(
            n_estimators=200,
            max_samples=512,
            contamination=0.05,
            random_state=42,
            verbose=1
        )
        dec_model.fit(X_dec_scaled)
        self.training_times['decryption'] = time() - start_time
        
       
        if y_dec.sum() > 0:
            rf_dec = RandomForestClassifier(n_estimators=100, random_state=42)
            rf_dec.fit(X_dec_scaled, y_dec)
            self.models['decryption'] = (dec_model, rf_dec)
        else:
            self.models['decryption'] = (dec_model, None)
    
    def evaluate_models(self, enc_data, dec_data):
        print("\n=== Model Efficiency Metrics ===\n")
        
       
        print("\nEncryption Model Evaluation:")
        X_enc = enc_data[self.features['encryption']]
        y_enc = enc_data['is_anomaly']
        X_enc_scaled = self.scalers['encryption'].transform(X_enc)
        
        
        start_time = time()
        scores = self.models['encryption'][0].decision_function(X_enc_scaled)
        inference_time = (time() - start_time) / len(X_enc) * 1000  
        
        y_pred = (scores < self.thresholds['encryption']).astype(int)
        
        print(f"Training Time: {self.training_times['encryption']:.2f} seconds")
        print(f"Inference Time: {inference_time:.4f} ms per sample")
        print(f"Number of Features: {len(self.features['encryption'])}")
        
        accuracy = accuracy_score(y_enc, y_pred)
        precision = precision_score(y_enc, y_pred)
        recall = recall_score(y_enc, y_pred)
        f1 = f1_score(y_enc, y_pred)
        auc_roc = roc_auc_score(y_enc, scores)
        ap = average_precision_score(y_enc, scores)
        
        print("\nPerformance Metrics:")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        print(f"AUC-ROC: {auc_roc:.4f}")
        print(f"Average Precision: {ap:.4f}")
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_enc, y_pred))
        print("\nClassification Report:")
        print(classification_report(y_enc, y_pred))
        
      
        self.plot_pr_curve(y_enc, scores, 'encryption')
        
    
        print("\n\nDecryption Model Evaluation:")
        X_dec = dec_data[self.features['decryption']]
        y_dec = dec_data['is_anomaly']
        X_dec_scaled = self.scalers['decryption'].transform(X_dec)
        
        
        start_time = time()
        scores = self.models['decryption'][0].decision_function(X_dec_scaled)
        inference_time = (time() - start_time) / len(X_dec) * 1000  
        
        y_pred = (scores < self.thresholds['decryption']).astype(int)
        
        print(f"Training Time: {self.training_times['decryption']:.2f} seconds")
        print(f"Inference Time: {inference_time:.4f} ms per sample")
        print(f"Number of Features: {len(self.features['decryption'])}")
        
       
        accuracy = accuracy_score(y_dec, y_pred)
        precision = precision_score(y_dec, y_pred)
        recall = recall_score(y_dec, y_pred)
        f1 = f1_score(y_dec, y_pred)
        auc_roc = roc_auc_score(y_dec, scores)
        ap = average_precision_score(y_dec, scores)
        
        print("\nPerformance Metrics:")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall: {recall:.4f}")
        print(f"F1 Score: {f1:.4f}")
        print(f"AUC-ROC: {auc_roc:.4f}")
        print(f"Average Precision: {ap:.4f}")
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_dec, y_pred))
        print("\nClassification Report:")
        print(classification_report(y_dec, y_pred))
        
        self.plot_pr_curve(y_dec, scores, 'decryption')
    
    def plot_pr_curve(self, y_true, scores, phase):
        precision, recall, _ = precision_recall_curve(y_true, scores)
        ap = average_precision_score(y_true, scores)
        
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, label=f'{phase.capitalize()} (AP = {ap:.2f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title(f'Precision-Recall Curve - {phase.capitalize()}')
        plt.legend()
        plt.grid()
        plt.savefig(f'{phase}_pr_curve.png')
        plt.close()
    
    def save_models(self):
        dump(self.models['encryption'][0], 'encryption_iforest.joblib')
        if self.models['encryption'][1] is not None:
            dump(self.models['encryption'][1], 'encryption_rf.joblib')
        dump(self.scalers['encryption'], 'encryption_scaler.joblib')
        
        dump(self.models['decryption'][0], 'decryption_iforest.joblib')
        if self.models['decryption'][1] is not None:
            dump(self.models['decryption'][1], 'decryption_rf.joblib')
        dump(self.scalers['decryption'], 'decryption_scaler.joblib')
    
    def plot_feature_importance(self):
        for phase in ['encryption', 'decryption']:
            model = self.models[phase][0]
            features = self.features[phase]
            
            importance = np.mean([tree.feature_importances_ for tree in model.estimators_], axis=0)
            plt.figure(figsize=(10, 6))
            sns.barplot(x=importance, y=features)
            plt.title(f"{phase.capitalize()} Isolation Forest Feature Importance")
            plt.tight_layout()
            plt.savefig(f'{phase}_feature_importance.png')
            plt.close()
            
           
            data = enc_data if phase == 'encryption' else dec_data
            for feature in features[:4]:  
                plt.figure(figsize=(10, 6))
                sns.boxplot(x='is_anomaly', y=feature, data=data)
                plt.title(f'{feature} Distribution by Anomaly Status - {phase}')
                plt.savefig(f'{phase}_{feature}_distribution.png')
                plt.close()

if __name__ == "__main__":
    detector = AnomalyDetector()
    enc_data, dec_data = detector.load_and_preprocess('qem_flask_dataset.csv')
    detector.train_models(enc_data, dec_data)
    detector.evaluate_models(enc_data, dec_data)
    detector.plot_feature_importance()
    detector.save_models()
    print("\nModels and scalers saved to disk.")
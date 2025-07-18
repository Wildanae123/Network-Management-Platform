# backend/app/core/ml_engine.py
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import logging

logger = logging.getLogger(__name__)

class MLEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.failure_predictor = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.models_trained = False
    
    async def detect_anomalies(self, device_id: int, current_metrics: Dict, historical_metrics: List[Dict]) -> List[Dict]:
        """Detect anomalies in device metrics"""
        try:
            if not historical_metrics:
                return []
            
            # Prepare data
            features = self.prepare_features_for_anomaly_detection(historical_metrics, current_metrics)
            
            if len(features) < 10:  # Need minimum data for anomaly detection
                return []
            
            # Train anomaly detector if not already trained
            if not hasattr(self, 'anomaly_detector_trained'):
                self.anomaly_detector.fit(features[:-1])  # All except current
                self.anomaly_detector_trained = True
            
            # Predict anomalies
            current_features = features[-1].reshape(1, -1)
            is_anomaly = self.anomaly_detector.predict(current_features)[0]
            
            anomalies = []
            if is_anomaly == -1:  # Anomaly detected
                anomaly_score = self.anomaly_detector.decision_function(current_features)[0]
                
                # Determine which metrics are anomalous
                anomalous_metrics = self.identify_anomalous_metrics(current_metrics, historical_metrics)
                
                for metric_name, metric_data in anomalous_metrics.items():
                    anomalies.append({
                        'device_id': device_id,
                        'metric': metric_name,
                        'current_value': metric_data['current_value'],
                        'expected_range': metric_data['expected_range'],
                        'anomaly_score': anomaly_score,
                        'severity': self.determine_anomaly_severity(anomaly_score),
                        'description': f"{metric_name} value {metric_data['current_value']} is outside expected range {metric_data['expected_range']}"
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return []
    
    def prepare_features_for_anomaly_detection(self, historical_metrics: List[Dict], current_metrics: Dict) -> np.ndarray:
        """Prepare features for anomaly detection"""
        # Convert to DataFrame
        df = pd.DataFrame(historical_metrics)
        
        # Pivot to get metric values by timestamp
        pivot_df = df.pivot_table(
            index='timestamp', 
            columns=['metric_type', 'metric_name'], 
            values='value', 
            aggfunc='mean'
        )
        
        # Fill missing values
        pivot_df = pivot_df.fillna(method='forward').fillna(0)
        
        # Add current metrics as the last row
        current_row = {}
        for metric_type, metrics in current_metrics.items():
            if isinstance(metrics, dict):
                for metric_name, value in metrics.items():
                    current_row[(metric_type, metric_name)] = value
        
        current_df = pd.DataFrame([current_row])
        current_df.index = [datetime.utcnow()]
        
        # Combine historical and current data
        combined_df = pd.concat([pivot_df, current_df]).fillna(0)
        
        return combined_df.values
    
    def identify_anomalous_metrics(self, current_metrics: Dict, historical_metrics: List[Dict]) -> Dict:
        """Identify which specific metrics are anomalous"""
        anomalous_metrics = {}
        
        # Calculate statistical bounds for each metric
        df = pd.DataFrame(historical_metrics)
        
        for metric_type in current_metrics:
            if isinstance(current_metrics[metric_type], dict):
                for metric_name, current_value in current_metrics[metric_type].items():
                    historical_values = df[
                        (df['metric_type'] == metric_type) & 
                        (df['metric_name'] == metric_name)
                    ]['value'].values
                    
                    if len(historical_values) > 5:  # Need minimum data
                        mean_val = np.mean(historical_values)
                        std_val = np.std(historical_values)
                        
                        # Define acceptable range (mean ± 2 * std)
                        lower_bound = mean_val - 2 * std_val
                        upper_bound = mean_val + 2 * std_val
                        
                        if current_value < lower_bound or current_value > upper_bound:
                            anomalous_metrics[f"{metric_type}_{metric_name}"] = {
                                'current_value': current_value,
                                'expected_range': f"{lower_bound:.2f} - {upper_bound:.2f}",
                                'historical_mean': mean_val,
                                'historical_std': std_val
                            }
        
        return anomalous_metrics
    
    def determine_anomaly_severity(self, anomaly_score: float) -> str:
        """Determine severity based on anomaly score"""
        if anomaly_score < -0.5:
            return 'critical'
        elif anomaly_score < -0.3:
            return 'high'
        elif anomaly_score < -0.1:
            return 'medium'
        else:
            return 'low'
    
    async def predict_failure(self, device_id: int, current_metrics: Dict, historical_data: List[Dict]) -> Dict:
        """Predict device failure probability"""
        try:
            if not historical_data:
                return {
                    'failure_probability': 0.0,
                    'time_to_failure': None,
                    'description': 'Insufficient historical data for prediction'
                }
            
            # Prepare features for failure prediction
            features, labels = self.prepare_features_for_failure_prediction(historical_data)
            
            if len(features) < 20:  # Need minimum data for prediction
                return {
                    'failure_probability': 0.0,
                    'time_to_failure': None,
                    'description': 'Insufficient data for reliable prediction'
                }
            
            # Train failure predictor if not already trained
            if not hasattr(self, 'failure_predictor_trained'):
                X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)
                
                self.failure_predictor.fit(X_train, y_train)
                self.failure_predictor_trained = True
                
                # Log model performance
                y_pred = self.failure_predictor.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                logger.info(f"Failure prediction model accuracy: {accuracy:.2f}")
            
            # Prepare current metrics for prediction
            current_features = self.prepare_current_features_for_prediction(current_metrics)
            
            # Predict failure probability
            failure_prob = self.failure_predictor.predict_proba([current_features])[0][1]  # Probability of failure
            
            # Estimate time to failure based on trend analysis
            time_to_failure = self.estimate_time_to_failure(historical_data, current_metrics)
            
            # Generate description
            description = self.generate_failure_description(failure_prob, time_to_failure)
            
            return {
                'failure_probability': failure_prob,
                'time_to_failure': time_to_failure,
                'description': description
            }
            
        except Exception as e:
            logger.error(f"Error predicting failure: {str(e)}")
            return {
                'failure_probability': 0.0,
                'time_to_failure': None,
                'description': f'Error in prediction: {str(e)}'
            }
    
    def prepare_features_for_failure_prediction(self, historical_data: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features and labels for failure prediction"""
        # Convert to DataFrame
        df = pd.DataFrame(historical_data)
        
        # Create features based on metric trends and patterns
        features = []
        labels = []
        
        # Group by time windows
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Create sliding windows
        window_size = 10  # 10 data points per window
        for i in range(len(df) - window_size):
            window_data = df.iloc[i:i+window_size]
            
            # Extract features from window
            feature_vector = []
            
            # Statistical features
            feature_vector.append(window_data['value'].mean())
            feature_vector.append(window_data['value'].std())
            feature_vector.append(window_data['value'].min())
            feature_vector.append(window_data['value'].max())
            
            # Trend features
            feature_vector.append(window_data['value'].iloc[-1] - window_data['value'].iloc[0])  # Change
            feature_vector.append(np.corrcoef(range(len(window_data)), window_data['value'])[0, 1])  # Trend
            
            features.append(feature_vector)
            
            # Create label (simplified: failure if next value is significantly different)
            next_value = df.iloc[i+window_size]['value']
            window_mean = window_data['value'].mean()
            window_std = window_data['value'].std()
            
            # Label as failure if next value is outside 3 sigma
            is_failure = abs(next_value - window_mean) > 3 * window_std
            labels.append(1 if is_failure else 0)
        
        return np.array(features), np.array(labels)
    
    def prepare_current_features_for_prediction(self, current_metrics: Dict) -> List[float]:
        """Prepare current metrics for failure prediction"""
        features = []
        
        # Extract key metrics
        cpu_usage = current_metrics.get('cpu', {}).get('usage', 0)
        memory_usage = current_metrics.get('memory', {}).get('usage_percent', 0)
        
        # Interface metrics
        interface_metrics = current_metrics.get('interfaces', {})
        avg_utilization = 0
        error_rate = 0
        
        if interface_metrics:
            utilizations = [intf.get('utilization', 0) for intf in interface_metrics.values()]
            error_rates = [intf.get('error_rate', 0) for intf in interface_metrics.values()]
            
            avg_utilization = np.mean(utilizations) if utilizations else 0
            error_rate = np.mean(error_rates) if error_rates else 0
        
        # Environmental metrics
        temperature = current_metrics.get('environment', {}).get('temperature', 0)
        
        features = [cpu_usage, memory_usage, avg_utilization, error_rate, temperature]
        
        return features
    
    def estimate_time_to_failure(self, historical_data: List[Dict], current_metrics: Dict) -> Optional[datetime]:
        """Estimate time to failure based on trend analysis"""
        try:
            df = pd.DataFrame(historical_data)
            
            # Focus on critical metrics
            critical_metrics = df[df['metric_type'].isin(['cpu', 'memory'])]
            
            if len(critical_metrics) < 5:
                return None
            
            # Calculate trend
            critical_metrics = critical_metrics.sort_values('timestamp')
            
            # Simple linear regression to estimate when metric will reach critical threshold
            x = np.arange(len(critical_metrics))
            y = critical_metrics['value'].values
            
            # Fit linear trend
            coefficients = np.polyfit(x, y, 1)
            slope = coefficients[0]
            
            if slope > 0:  # Increasing trend
                current_value = y[-1]
                critical_threshold = 95  # 95% threshold
                
                if current_value < critical_threshold:
                    time_periods_to_failure = (critical_threshold - current_value) / slope
                    
                    # Assume each data point represents 1 hour (adjust based on your collection interval)
                    hours_to_failure = time_periods_to_failure * 1  # 1 hour per data point
                    
                    return datetime.utcnow() + timedelta(hours=hours_to_failure)
            
            return None
            
        except Exception as e:
            logger.error(f"Error estimating time to failure: {str(e)}")
            return None
    
    def generate_failure_description(self, failure_prob: float, time_to_failure: Optional[datetime]) -> str:
        """Generate human-readable failure description"""
        if failure_prob < 0.3:
            risk_level = "Low"
        elif failure_prob < 0.6:
            risk_level = "Medium"
        elif failure_prob < 0.8:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        description = f"{risk_level} risk of failure (probability: {failure_prob:.1%})"
        
        if time_to_failure:
            time_diff = time_to_failure - datetime.utcnow()
            if time_diff.days > 0:
                description += f". Estimated time to failure: {time_diff.days} days"
            elif time_diff.seconds > 3600:
                hours = time_diff.seconds // 3600
                description += f". Estimated time to failure: {hours} hours"
            else:
                description += ". Failure may occur soon"
        
        return description
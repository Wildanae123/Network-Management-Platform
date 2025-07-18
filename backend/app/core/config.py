# backend/app/core/config.py
import os
from pathlib import Path
from pydantic import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Database
    database_url: str
    database_host: str = "localhost"
    database_port: int = 5432
    database_name: str = "network_management"
    database_user: str = "netadmin"
    database_password: str
    
    # API
    api_host: str = "localhost"
    api_port: int = 5000
    backend_secret_key: str
    
    # Device Configuration
    commands_config_path: str = "./backend/config/commands.yaml"
    default_device_username: str = "admin"
    default_device_password: str
    device_timeout: int = 30
    
    # Monitoring
    enable_monitoring: bool = True
    monitoring_interval: int = 300
    
    # ML & Analytics
    enable_ml_predictions: bool = True
    ml_model_path: str = "./analytics/ml_models"
    
    class Config:
        env_file = [
            ".env.local",     # Highest priority
            ".env",           # Default
            "backend/.env"    # Backend specific
        ]
        env_file_encoding = 'utf-8'
        case_sensitive = False

# Create global settings instance
settings = Settings()
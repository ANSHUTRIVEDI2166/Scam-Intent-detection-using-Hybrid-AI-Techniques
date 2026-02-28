"""
Configuration settings for the Scammer Detector Honeypot System.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration."""
    
    # API Settings
    API_KEY: str = os.getenv("API_KEY", "your-secret-api-key-here")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # NVIDIA NIMs Settings
    NVIDIA_API_KEY: str = os.getenv("NVIDIA_API_KEY", "")
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    NVIDIA_MODEL: str = os.getenv("NVIDIA_MODEL", "meta/llama-3.3-70b-instruct")
    # Fallback alternatives: "meta/llama-3.1-8b-instruct", "mistralai/mixtral-8x7b-instruct"
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.7"))
    
    # Conversation Settings
    MAX_MESSAGES: int = int(os.getenv("MAX_MESSAGES", "50"))
    MIN_MESSAGES_FOR_INTELLIGENCE: int = int(os.getenv("MIN_MESSAGES_FOR_INTELLIGENCE", "2"))
    
    # Scam Detection Thresholds
    SCAM_CONFIDENCE_THRESHOLD: float = float(os.getenv("SCAM_CONFIDENCE_THRESHOLD", "0.15"))
    INTELLIGENCE_SUFFICIENCY_THRESHOLD: int = int(os.getenv("INTELLIGENCE_SUFFICIENCY_THRESHOLD", "10"))
    
    # Local JSON Storage
    DATA_DIR: str = os.getenv("DATA_DIR", "data")
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


config = Config()



"""Configuration settings for Integration Service"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    
    redis_url: str = "redis://localhost:6379"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()


from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    # App Settings
    APP_ENV: str = "local" # local, development, production
    
    # LLM Settings
    DEEPSEEK_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    
    # GitHub Settings
    GITHUB_TOKEN: Optional[str] = None
    
    # Local Settings
    WORK_DIR: str = "work_dir"

    # AWS Settings (Optional for local dev)
    AWS_REGION: str = "us-east-1"
    S3_VECTOR_BUCKET_NAME: Optional[str] = None
    S3_SOURCE_BUCKET_NAME: Optional[str] = None
    S3_RESULTS_BUCKET_NAME: Optional[str] = None
    SQS_QUEUE_URL: Optional[str] = None
    
    # Agent Settings
    MAX_RETRIES: int = 2
    CONFIDENCE_THRESHOLD: float = 0.7
    
    model_config = SettingsConfigDict(env_file=[".env", "../.env"], env_ignore_empty=True, extra="ignore")

settings = Settings()

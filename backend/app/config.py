from pydantic_settings import BaseSettings
from functools import lru_cache
import os
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY")
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "https://rljuhbbetqssqqsqgpdm.supabase.co")
    SUPABASE_KEY: str = os.getenv("SUPABASE_PRIVATE_KEY")
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()

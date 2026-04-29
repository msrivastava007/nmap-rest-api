from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    NMAP_PATH: str = "nmap"
    NMAP_FLAGS_DEMO: str = "-F --open -oX -"
    NMAP_FLAGS_PRODUCTION: str = "-sV -T4 --open -oX -"
    NMAP_TIMEOUT_SECS: int = 60
    DATABASE_URL: str = "sqlite:///./nmap.db"
    LOG_LEVEL: str = "INFO"
    MAX_HISTORY: int = 50
    BLOCK_PRIVATE_RANGES: bool = False
    RAW_XML_RETENTION_DAYS: int = 30
    DEMO_MODE: bool = True


settings = Settings()

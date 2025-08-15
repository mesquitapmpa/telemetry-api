from pydantic import BaseModel
import os

class Settings(BaseModel):
    http_port: int = int(os.getenv("HTTP_PORT", "8000"))

settings = Settings()
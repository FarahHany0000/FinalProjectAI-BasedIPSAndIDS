import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "ids-secret-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URI", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'ids.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    AGENT_KEY = os.environ.get("AGENT_KEY", "changeme")
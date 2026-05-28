import os

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# API Configuration
API_HOST = "0.0.0.0"
API_PORT = 8000
API_DEBUG = True

# Model Paths (now all inside the project)
IDS_MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")

# Internal Model Paths (Attack Model)
ATTACK_MODEL_DIR = os.path.join(BASE_DIR, "ml", "models")
ATTACK_PREPROCESS_DIR = os.path.join(BASE_DIR, "ml", "preprocessors")
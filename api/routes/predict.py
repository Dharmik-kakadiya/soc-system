import sys
import os
from fastapi import APIRouter, HTTPException
from typing import Dict, Any

# Ensure we can import the ML pipeline
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.append(BASE_DIR)

from ml.pipeline.predict import predict

router = APIRouter()

@router.post("/predict")
def predict_endpoint(payload: Dict[str, Any]):
    """
    Receives network data as JSON, runs it through the ML pipeline,
    and returns whether it is an attack or benign.
    """
    try:
        result = predict(payload)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

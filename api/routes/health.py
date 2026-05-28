from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
def health_check():
    """
    Simple health check to verify if the API server is alive.
    """
    return {"status": "ok"}

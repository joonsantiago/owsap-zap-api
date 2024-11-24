from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_route():
    return "OK"

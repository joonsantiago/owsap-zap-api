from fastapi import APIRouter, Depends
from auth import get_user

from models import za_proxy

from models.dto.dast import ItemDast

router = APIRouter()


@router.get("/")
async def get_route(user: dict = Depends(get_user)):
    return user

@router.post("/run-scan")
async def post_route(
    payload: ItemDast,
    user: dict = Depends(get_user)
):
    response = za_proxy.ZaProxy.start_scan_target(
        payload
    )

    return response


@router.get("/scan-status/{scan_id}/{context}")
async def get_route(
    scan_id: int,
    context: str,
    user: dict = Depends(get_user)
):
    response = za_proxy.ZaProxy.progress_scan(
        scan_id, 
        context,
    )

    return response

@router.get("/scan-report/{scan_id}/{context}")
async def get_route(
    scan_id: int,
    context: str,
    user: dict = Depends(get_user)
):
    response = za_proxy.ZaProxy.progress_scan(
        scan_id, 
        context,
        False
    )

    return response
from typing import Union
from fastapi import FastAPI, Depends
from routers import public, dast
from auth import get_user

app = FastAPI()

app.include_router(
    public.router,
    prefix="/api/v1/public"
)
app.include_router(
    dast.router,
    prefix="/api/v1/dast",
    dependencies=[Depends(get_user)]
)

@app.get("/")
def read_root():
    return {"Hello": "World"}


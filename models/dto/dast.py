
from pydantic import BaseModel

from typing import Optional, Union, List

class RequestCookies(BaseModel):
    name: str
    value: str

class RequestCookie(BaseModel):
    domain: str
    records: Optional[List[RequestCookies]] = None

class RequestHeaders(BaseModel):
    name: str
    value: str

class ItemDast(BaseModel):
    target: str
    context: str
    cookies: Optional[RequestCookie] = None
    headers: Optional[List[RequestHeaders]] = None
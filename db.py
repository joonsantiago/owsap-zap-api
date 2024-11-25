import os
from dotenv import load_dotenv

load_dotenv()

API_KEY_001: str = os.getenv('API_KEY_01') if os.getenv('API_KEY_01') else 'API_KEY_001'
API_KEY_002: str = os.getenv('API_KEY_02') if os.getenv('API_KEY_02') else 'API_KEY_002'

api_keys = {}
api_keys[API_KEY_001] =  "7oDYjo3d9r58EJKYi5x4E8"
api_keys[API_KEY_002] =  "mUP7PpTHmFAkxcQLWKMY8t"

users = {
    "7oDYjo3d9r58EJKYi5x4E8": {
        "name": "Bob"
    },
    "mUP7PpTHmFAkxcQLWKMY8t": {
        "name": "Alice"
    },
}

def check_api_key(api_key: str):
    return api_key in api_keys

def get_user_from_api_key(api_key: str):
    return users[api_keys[api_key]]

api_keys = {
    "API_KEY_01": "7oDYjo3d9r58EJKYi5x4E8",
    "API_KEY_02": "mUP7PpTHmFAkxcQLWKMY8t"
}

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

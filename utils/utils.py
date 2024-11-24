
class Response():

    def __init__(self) -> None:
        self.status = 200
        self.success = True
        self.message = ""
        self.data = None
        pass

    success= True,
    message= "",
    status=  200,
    data= []

def isValidStr(value) -> bool:
    valid = False
    try:
        valid =  value is not None \
            and value != "" \
            and len(value) > 3 \
            and value != "null" \
            and value != "undefined"            
    except:
        valid = False

    return valid

def isValidInt(value) -> bool:
    valid = False
    try:
        int(value)
        valid = True            
    except:
        valid = False

    return valid

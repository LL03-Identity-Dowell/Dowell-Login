import urllib.request
import random
import math
from cryptography.fernet import Fernet
import json
from . dowellconnection import dowellconnection

#For Master Login
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

#Env variables
from core.settings import DEFAULT_SALT

def host_check(host):
    try:
        urllib.request.urlopen(host)
        return "Connected"
    except:
        return "Error"
    
def dowellclock():
    oldt = 1609459200
    import time
    t1 = time.time()
    dowell = t1-oldt
    return dowell

def encode(key,text):
    cipher_suite = Fernet(key.encode())
    encoded_text = cipher_suite.encrypt(text.encode())
    return encoded_text

key="l6h8C92XGJmQ_aXpPN7_VUMzA8LS8Bg50A83KNcrVhQ="
r = encode(key,"Iloveyou")

def decode(key,decodetext):
    cipher_suite = Fernet(key.encode())
    decoded_text = cipher_suite.decrypt(decodetext.encode())
    return decoded_text.decode()

# Generate random OTP
def generateOTP() :
     digits = "0123456789"
     OTP = ""
     for i in range(6) :
        OTP += digits[math.floor(random.random() * 10)]
     return OTP

# Security layer before logging in user
def dowellsecuritylayer(profile_id,location,connectivity,device,OS,ProcessID):
    field={'profile_id':profile_id,'location':location}
    locRights=dowellconnection("login","bangalore","login","locations","locations","1107","ABCDE","fetch",field,"nil")
    loc_Rights=json.loads(locRights)

    if loc_Rights["data"]>0:
        field={'profile_id':profile_id,'Connectivity':connectivity}
        connRights=dowellconnection("login","bangalore","login","connections","connections","1110","ABCDE","fetch",field,"nil")
        conn_Rights=json.loads(connRights)

        if conn_Rights["data"]>0:
            field={'profile_id':profile_id,'Device':device}
            devRights=dowellconnection("login","bangalore","login","devices","devices","1106","ABCDE","fetch",field,"nil")
            dev_Rights=json.loads(devRights)

            if dev_Rights["data"]>0:
                field={'profile_id':profile_id,'OS':OS}
                OSRights=dowellconnection("login","bangalore","login","os","os","1108","ABCDE","fetch",field,"nil")
                OS_Rights=json.loads(OSRights)

                if OS_Rights["data"]>0:
                    field={'profile_id':profile_id,'ProcessID':ProcessID}
                    PIDRights=dowellconnection("login","bangalore","login","processes","processes","1111","ABCDE","fetch",field,"nil")
                    PID_Rights=json.loads(PIDRights)

                    if PID_Rights["data"]>0:
                        # finalRights=dowellintersection('locRights','connRights','devRights','osRights','processRights','userRights')
                        # loginsessionID= profile_id+languageID + sessionID + role_id +city_id + designation_id
                        loginsessionID=profile_id+1033+ 111+ 1001 +2232+4004
                        # final_field=["loginsessionID","finalRights","Device","OS","Connectivity","Location","EVENT","DATE+TIME","Dowelltime"]
                        return (loginsessionID)
                        # dowellconnection("login","bangalore","login","dowell_users","dowell_users","1116","ABCDE","insert",final_field,"nil")

                    return("Process ID not found")
                return("OS not found")
            return('Device not found')
        return("Connection not found")
    return("Location Not found in Database")
def get_next_pro_id(res_list):
    lis=[]
    for value in res_list:
        if 'profile_id' in value.keys() :
            lis.append(value['profile_id'])
    return(max([int(item) for item in lis])+1)

def get_next_company_id(res_list):
    lis=[]
    for value in res_list:
        if 'company_id' in value.keys() :
            lis.append(value['company_id'])
    return(max([int(item) for item in lis])+1)

#For master login
def generate_key(password: str) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=str.encode(DEFAULT_SALT),
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def decrypt_message(encrypted_message: bytes, password: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()
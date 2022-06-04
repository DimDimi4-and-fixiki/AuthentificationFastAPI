import os

from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv

load_dotenv()
TOKEN_URL = os.getenv('TOKEN_URL')

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL)


@app.post('/token')
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    token_result = {
        'access_token': form_data.username + 'token'
    }
    return token_result


@app.get('/')
async def index(token: str = Depends(oauth2_scheme)):
    auth_result = {
        'your_token': token
    }
    return auth_result

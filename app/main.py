import os
import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
from tortoise.contrib.fastapi import register_tortoise
from models import User, User_Pydantic, UserIn_Pydantic
from passlib.hash import bcrypt

load_dotenv()
TOKEN_URL = os.getenv('TOKEN_URL')
JWT_SECRET = os.getenv('JWT_SECRET')

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL)


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    elif not user.verify_password(password):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        user_data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id=user_data.get('id'))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid user credentials')

    return await User_Pydantic.from_tortoise_orm(user)


@app.post('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user


@app.post('/token')
async def get_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Template of the result
    result = {
        'Status': 'Error',
        'Message': 'Invalid user credentials'
    }

    # Get user if the user is authenticated
    user = await authenticate_user(form_data.username, form_data.password)

    # If user was not authenticated, return Error status
    if not user:
        return result

    user_obj = await User_Pydantic.from_tortoise_orm(user)

    token = jwt.encode(user_obj.dict(), JWT_SECRET, algorithm='HS256')

    # Fill result with generated JWT token
    result['Status'] = 'Success'
    result['Message'] = 'Token was generated successfully'
    result['access_token'] = token
    result['user_details'] = user_obj.dict()
    result['token_type'] = 'bearer'

    return result


@app.get('/')
async def index(token: str = Depends(oauth2_scheme)):
    auth_result = {
        'your_token': token
    }
    return auth_result


@app.post('/users', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(username=user.username, password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)


register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['models']},
    generate_schemas=True,
    add_exception_handlers=True
)

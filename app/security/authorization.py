from datetime import datetime, timedelta
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from jose import JWTError, jwt
from passlib.context import CryptContext

from database.requests import UserLogin, UserSignUp


from pydantic import BaseModel


SECRET_KEY = 'd967bed2172e5b69ec4e5c6a9ea598449a6b8847f05474f1bd0088fb58d8d0cd'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30


db = {
    'bo': {
        'username': 'bo',
        'full_name': 'bo knows',
        'email': 'bo@gmail.com',
        'hashed_password': '$2b$12$rjs8o079tKUxHhEbHOIJ4e7CtTwKD9wzHFCgWyyJvj.xzwGe.yyRe',
        'disabled': False,
        'role': 'admin'
    },
    'u2': {
        'username': 'u2',
        'full_name': 'User 2',
        'email': 'u2@gmail.com',
        'hashed_password': '$2b$12$lMf0hevLrXSaXv/b5U7Xv.HRCqQgIMmARqnJjhnh.7jeBHsPLOMlS',
        'disabled': False,
        'role': 'user'
    }
}

class UserInDB(BaseModel):
    pass

class User(BaseModel):
    pass

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str or None = None
    

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl='login')


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        pass
    
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    
    return user

def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
        
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth_2_scheme)):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={'WWW-Authenticate': 'Bearer'}
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credential_exception
        
        token_data = TokenData(username=username)
        
    except JWTError:
        raise credential_exception
    
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credential_exception
    
    return user


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='inactive user'
        )
    return current_user


@app.post('/token', response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'}
        )
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={'sub': user.username}, expires_delta=access_token_expires)
    return {'access_token': access_token, 'token_type': 'bearer'}


@app.get('/users/me/', response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get('/users/me/items')
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{'item_id': 1, 'owner': current_user}]


class CheckPermission:
    def __init__(self, permissions: List) -> None:
        self.permissions = permissions
        
    def __call__(self, user: UserInDB = Depends(get_current_active_user)) -> bool:
        for permission in self.permissions:
            if permission not in user.role:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='Permission Denied'
                )
            return True
        
@app.get('/admin')
def admin(authorized: bool = Depends(CheckPermission(permissions=['admin',]))):
    return {'message': 'permission granted'}
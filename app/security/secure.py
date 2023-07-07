import os
from datetime import datetime, timedelta
from typing import Annotated, List
from dotenv import load_dotenv

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from database.db_config import Session
from database.models import User
from database.requests import Token, TokenData

from repository.users import UsersRepository

from jose import JWTError, jwt
from passlib.context import CryptContext


load_dotenv()

SECRET_KEY = os.environ['SECRET_KEY']
ALGORITHM = os.environ['ALGORITHM']


pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl='login')

async def get_password_hash(password):
    return pwd_context.hash(password)

async def verify_password(plain_password, hashed_password):
    return await pwd_context.verify(plain_password, hashed_password)

async def get_user(username: str):
    async with Session() as session:
        async with session.begin():
            repo = UsersRepository(session)
            return await repo.get_user_by_username(username)
        
async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user

async def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
        
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth_2_scheme)]):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid credentials',
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
    
    user = await get_user(token_data.username)
    if user is None:
        raise credential_exception
    
    return user

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Inactive user'
        )
    return current_user


class CheckPermission:
    def __init__(self, permission: str) -> None:
        self.permission = permission
        
    def __call__(self, user: Annotated[User, Depends(get_current_active_user)]) -> bool:
        perm_list = [perm for perm in user.role.permissions]
        if len(perm_list) > 0:
            for perm in perm_list:
                if perm.name == self.permission:
                    return True  
    
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Permission denied'
        )
        
class CheckRole:
    def __init__(self, role: str) -> None:
        self.role = role
        
    def __call__(self, user: Annotated[User, Depends(get_current_active_user)]) -> bool:
        if self.role != user.role.name:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Permission denied'
            )
        return True
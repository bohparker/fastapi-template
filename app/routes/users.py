from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from fastapi.security import OAuth2PasswordRequestForm

from security.secure import get_password_hash, get_user, \
    authenticate_user, create_access_token, get_current_active_user, \
        CheckPermission, CheckRole

from database.db_config import Session
from database.models import User
from database.requests import UserSignUp, Token

from repository.users import UsersRepository


router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = 30



@router.post('/signup', status_code=201)
async def signup(req: UserSignUp):
    async with Session() as session:
        async with session.begin():
            repo = UsersRepository(session)
            
            hash = await get_password_hash(req.password)
            req.password = hash
            result = await repo.add_user(req)
            
            if result == 'user-exists':
                raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail='User already exists'
            )
            return {'message': f'User created: {req.username}'}
        
@router.post('/login', response_model=Token)
async def login_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'}
        )
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={'sub': user.username}, expires_delta=access_token_expires
    )
    return {'access_token': access_token, 'token_type': 'bearer'}
        


# TEST ROUTES

# user must have admin role to access this route
@router.get('/test/user-role')
async def retrieve_user_role(req: str, authorized: Annotated[bool, Depends(CheckRole(role='admin'))]):
    user = await get_user(req)
    if user:
        return user
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail='User not found'
    )
    
# user must have admin permission to access this route
@router.get('/test/user-perm')
async def retrieve_user_perm(
    req: str,
    authorized: Annotated[bool,Depends(CheckPermission(permission='admin'))]):
    user = await get_user(req)
    if user:
        return user
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail='User not found'
    )
from pydantic import BaseModel


class UserSignUp(BaseModel):
    username: str
    password: str
    
    class Config:
        schema_extra = {
            'example': {
                'username': 'testuser',
                'password': 'password123'
            }
        }
    
class UserLogin(BaseModel):
    username: str
    password: str
    
    class Config:
        schema_extra = {
            'example': {
                'username': 'testuser',
                'password': 'password123'
            }
        }

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str or None = None
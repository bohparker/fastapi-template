from sqlalchemy import select

from database.models import User
from database.requests import UserSignUp


class UsersRepository:
    
    def __init__(self, session):
        self.session = session
        
    async def get_user_by_username(self, req: str) -> User:
        q = select(User).where(User.username == req)
        return await self.session.scalar(q)
        
    async def add_user(self, req: UserSignUp) -> bool:
        q = select(User).where(User.username == req.username)
        existing_user = await self.session.scalar(q)
        if existing_user:
            return 'user-exists'
            
        new_user = User(username=req.username, password_hash=req.password, role_id=int(2))
        self.session.add(new_user)
        
        return 'user-created'
import asyncio
from sqlalchemy import delete
from db_config import Session, Model, engine
from models import RolePermission, Role, Permission, User


async def main():
    async with engine.begin() as connection:
        await connection.run_sync(Model.metadata.drop_all)
        await connection.run_sync(Model.metadata.create_all)
    
    async with Session() as session:
        async with session.begin():
            
            admin = Role(name='admin')
            permission = Permission(name='admin')
            
            session.add(admin)
            admin.permissions.append(permission)
            
            user = Role(name='user')
            session.add(user)
            
            
    
    
if __name__ == '__main__':
    asyncio.run(main())
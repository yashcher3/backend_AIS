from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from auth_config import SECRET_KEY, ALGORITHM, get_user
from auth_models import TokenData

security = HTTPBearer()



async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    print(f"=== GET_CURRENT_USER CALLED ===")
    print(f"Token: {credentials.credentials}")

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Неверные учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Decoded payload: {payload}")

        username: str = payload.get("sub")
        role: str = payload.get("role")
        print(f"Username from token: {username}")
        print(f"Role from token: {role}")

        if username is None:
            print("Username is None - raising exception")
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
        print(f"Token data created: {token_data}")

    except JWTError as e:
        print(f"JWTError in get_current_user: {str(e)}")
        raise credentials_exception

    user = get_user(username=token_data.username)
    print(f"User from get_user: {user}")

    if user is None:
        print(f"User {token_data.username} not found - raising exception")
        raise credentials_exception

    print(f"=== GET_CURRENT_USER SUCCESS - Returning user ===")
    return user


async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_active", True):
        raise HTTPException(status_code=400, detail="Неактивный пользователь")
    return current_user


def require_role(required_role: str):
    def role_checker(current_user: dict = Depends(get_current_active_user)):
        if current_user.get("role") != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Недостаточно прав"
            )
        return current_user

    return role_checker



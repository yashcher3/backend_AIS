

from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Секретный ключ для JWT (в продакшене хранить в env переменных)
SECRET_KEY = "your-secret-key-here-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 3
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


# Генерируем правильные хэши паролей
ADMIN_PASSWORD_HASH = get_password_hash("admintestpassword")
MANAGER_PASSWORD_HASH = get_password_hash("managertestpassword")
EXECUTOR_PASSWORD_HASH = get_password_hash("executortestpassword")

print(f"Admin hash: {ADMIN_PASSWORD_HASH}")
print(f"Manager hash: {MANAGER_PASSWORD_HASH}")
print(f"Executor hash: {EXECUTOR_PASSWORD_HASH}")
print(f"SECRET_KEY: {SECRET_KEY}")

# Хардкод пользователей с правильными хэшами
USERS_DATA = {
    "admin": {
        "username": "admin",
        "hashed_password": ADMIN_PASSWORD_HASH,
        "role": "admin",
        "is_active": True
    },
    "manager": {
        "username": "manager",
        "hashed_password": MANAGER_PASSWORD_HASH,
        "role": "manager",
        "is_active": True
    },
    "executor_1": {
        "username": "executor_1",
        "hashed_password": EXECUTOR_PASSWORD_HASH,
        "role": "user",
        "is_active": True
    },
    "executor_2": {
        "username": "executor_2",
        "hashed_password": EXECUTOR_PASSWORD_HASH,
        "role": "user",
        "is_active": True
    }
}


def get_user(username: str):


    if username in USERS_DATA:
        user_dict = USERS_DATA[username]
        print(f"User found: {user_dict}")
        return user_dict

    print(f"User {username} NOT FOUND")
    return None


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Новые функции для проверки ролей
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Получение текущего пользователя из токена"""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")

        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = get_user(username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    """Проверка активности пользователя"""
    if not current_user.get("is_active", True):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_role(required_role: str):
    """Декоратор для проверки конкретной роли"""

    def role_checker(current_user: dict = Depends(get_current_active_user)):
        if current_user.get("role") != required_role:
            raise HTTPException(
                status_code=403,
                detail=f"Недостаточно прав. Требуется роль: {required_role}"
            )
        return current_user

    return role_checker


def require_admin_or_manager():
    """Декоратор для проверки роли admin или manager"""

    def role_checker(current_user: dict = Depends(get_current_active_user)):
        if current_user.get("role") not in ["admin", "manager"]:
            raise HTTPException(
                status_code=403,
                detail="Недостаточно прав. Требуется роль admin или manager"
            )
        return current_user

    return role_checker


def require_admin_only():
    """Декоратор только для администраторов (не для руководителей)"""

    def role_checker(current_user: dict = Depends(get_current_active_user)):
        if current_user.get("role") != "admin":
            raise HTTPException(
                status_code=403,
                detail="Недостаточно прав. Требуется роль администратора"
            )
        return current_user

    return role_checker


# Упрощенная авторизация для обратной совместимости
async def simple_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Упрощенная авторизация для тестирования"""

    print(f"Token received: {credentials.credentials}")

    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Token decoded successfully: {payload}")

        username = payload.get("sub")
        role = payload.get("role")
        print(f"Username: {username}, Role: {role}")

        return {
            "username": username,
            "role": role,
            "is_active": True
        }
    except jwt.ExpiredSignatureError:
        print("Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except JWTError as e:
        print(f"JWTError: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Token error: {str(e)}")


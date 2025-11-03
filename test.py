from jose import JWTError, jwt
from datetime import datetime

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc2MTU5MTMwNH0.paGa2o-VKfN_n68KdUJRkHeCaOA-OyBzAxWVDi82ENc"
SECRET_KEY = "your-secret-key-here-change-in-production"

try:
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    print("Token is valid:")
    print(f"Username: {payload.get('sub')}")
    print(f"Role: {payload.get('role')}")
    print(f"Expires: {datetime.fromtimestamp(payload.get('exp'))}")
except jwt.ExpiredSignatureError:
    print("Token expired")
except jwt.InvalidTokenError as e:
    print(f"Invalid token: {e}")
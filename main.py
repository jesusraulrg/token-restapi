from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import sqlite3
import secrets
import hashlib

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

def get_connection():
    conn = sqlite3.connect('users.db')
    return conn

security = HTTPBasic()
security_bearer = HTTPBearer()

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def generate_token():
    return secrets.token_urlsafe(32)

@app.get("/root")
def root(credentials: HTTPAuthorizationCredentials = Depends(security_bearer), conn: sqlite3.Connection = Depends(get_connection)):
    user_token = credentials.credentials

    with conn:
        c = conn.cursor()
        c.execute("SELECT token FROM users WHERE token = ?", (user_token,))
        result = c.fetchone()

    if result and user_token == result[0]:
        return {"message": "TOKEN válido"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="TOKEN no válido")

@app.get("/token")
def token(credentials: HTTPBasicCredentials = Depends(security), conn: sqlite3.Connection = Depends(get_connection)):
    username = credentials.username
    password = credentials.password

    hashed_password = hash_password(password)
    
    with conn:
        c = conn.cursor()
        c.execute("SELECT token FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        result = c.fetchone()

    if result:
        token = result[0]
        return {"token": token}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario o contraseña incorrectos")

@app.post("/register")
def register(user: User, conn: sqlite3.Connection = Depends(get_connection)):
    username = user.username
    password = user.password
    
    token = generate_token()
    hashed_password = hash_password(password)

    with conn:
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, token) VALUES (?, ?, ?)", (username, hashed_password, token))
        conn.commit()

    return {"message": "Usuario registrado"}

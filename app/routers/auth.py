from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from app.config import config
from app.db import SessionLocal
from app.models.db_models import UserModel


router = APIRouter(prefix="/api/auth", tags=["Auth"])

# 使用 pbkdf2_sha256，避免当前环境下 bcrypt 后端的兼容性问题，
# 同时提供足够安全的密码哈希。
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class User(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool


class TokenData(BaseModel):
    username: Optional[str] = None


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)
    role: str = Field("readonly", pattern="^(admin|readonly)$")
    is_active: bool = True


class UserUpdate(BaseModel):
    """仅 admin 可调用，用于修改现有用户"""
    password: Optional[str] = Field(None, min_length=1, max_length=256)
    role: Optional[str] = Field(None, pattern="^(admin|readonly)$")
    is_active: Optional[bool] = None


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user_by_username(db, username: str) -> Optional[UserModel]:
    return db.query(UserModel).filter(UserModel.username == username).first()


def authenticate_user(db, username: str, password: str) -> Optional[UserModel]:
    user = get_user_by_username(db, username)
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash or ""):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=30))
    to_encode.update({"exp": expire})
    secret_key = getattr(config, "JWT_SECRET", None) or "CHANGE_ME_SECRET"
    algorithm = getattr(config, "JWT_ALGORITHM", None) or "HS256"
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme), db=Depends(_get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    secret_key = getattr(config, "JWT_SECRET", None) or "CHANGE_ME_SECRET"
    algorithm = getattr(config, "JWT_ALGORITHM", None) or "HS256"
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        username: str = payload.get("sub")  # type: ignore[assignment]
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_model = get_user_by_username(db, username=username)
    if user_model is None:
        raise credentials_exception

    return User(
        id=user_model.id,
        username=user_model.username,
        role=user_model.role,
        is_active=user_model.is_active,
    )


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="用户已被禁用")
    return current_user


async def require_admin(current_user: User = Depends(get_current_active_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="需要 admin 权限")
    return current_user


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(_get_db)):
    """
    用户登录，返回 JWT。

    默认支持两种角色：
    - admin: 拥有全部写入权限
    - readonly: 只能执行只读操作
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 更新最后登录时间
    user.last_login_at = datetime.utcnow()
    db.add(user)
    db.commit()

    access_token_expires = timedelta(
        minutes=int(getattr(config, "JWT_EXPIRE_MINUTES", 60))
    )
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token)


@router.get("/me", response_model=User)
async def read_current_user(current_user: User = Depends(get_current_active_user)):
    """
    获取当前登录用户信息。
    """
    return current_user


def ensure_initial_admin():
    """
    如果用户表为空，则自动创建一个默认 admin 用户：
    用户名: admin
    密码: admin
    仅在首次部署/无用户时生效。
    """
    db = SessionLocal()
    try:
        count = db.query(UserModel).count()
        if count > 0:
            return
        admin_user = UserModel(
            username="admin",
            password_hash=get_password_hash("admin"),
            role="admin",
            is_active=True,
        )
        db.add(admin_user)
        db.commit()
    finally:
        db.close()


@router.post("/users", response_model=User)
async def create_user(
    payload: UserCreate,
    current_admin: User = Depends(require_admin),
    db=Depends(_get_db),
):
    """
    创建新用户，仅 admin 可调用。
    """
    exists = get_user_by_username(db, payload.username)
    if exists:
        raise HTTPException(status_code=400, detail="用户名已存在")

    user_model = UserModel(
        username=payload.username,
        password_hash=get_password_hash(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(user_model)
    db.commit()
    db.refresh(user_model)

    return User(
        id=user_model.id,
        username=user_model.username,
        role=user_model.role,
        is_active=user_model.is_active,
    )


@router.get("/users", response_model=list[User])
async def list_users(
    current_admin: User = Depends(require_admin),
    db=Depends(_get_db),
):
    """
    列出所有用户，仅 admin 可调用。
    """
    rows = db.query(UserModel).order_by(UserModel.id).all()
    return [
        User(
            id=u.id,
            username=u.username,
            role=u.role,
            is_active=u.is_active,
        )
        for u in rows
    ]


@router.patch("/users/{username}", response_model=User)
async def update_user(
    username: str,
    payload: UserUpdate,
    current_admin: User = Depends(require_admin),
    db=Depends(_get_db),
):
    """
    修改现有用户（密码、角色、状态），仅 admin 可调用。
    不能禁用最后一个 admin 或将其降级为 readonly。
    """
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    if payload.password is None and payload.role is None and payload.is_active is None:
        raise HTTPException(status_code=400, detail="请至少指定一项要修改的内容（密码、角色或状态）")

    # 若修改角色或状态，需保护最后一个 admin
    if user.role == "admin":
        admin_count = db.query(UserModel).filter(UserModel.role == "admin").count()
        if admin_count <= 1:
            if payload.role == "readonly":
                raise HTTPException(status_code=400, detail="不能将最后一个 admin 降级为 readonly")
            if payload.is_active is False:
                raise HTTPException(status_code=400, detail="不能禁用最后一个 admin")

    if payload.password is not None:
        user.password_hash = get_password_hash(payload.password)
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    db.add(user)
    db.commit()
    db.refresh(user)

    return User(
        id=user.id,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
    )


@router.delete("/users/{username}")
async def delete_user(
    username: str,
    current_admin: User = Depends(require_admin),
    db=Depends(_get_db),
):
    """
    删除用户，仅 admin 可调用。
    不允许删除系统中最后一个 admin 用户。
    """
    user = get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    if user.role == "admin":
        admin_count = db.query(UserModel).filter(UserModel.role == "admin").count()
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="不能删除最后一个 admin 用户")

    db.delete(user)
    db.commit()

    return {"detail": "用户已删除"}


__all__ = [
    "router",
    "get_current_user",
    "get_current_active_user",
    "require_admin",
    "get_password_hash",
    "ensure_initial_admin",
]


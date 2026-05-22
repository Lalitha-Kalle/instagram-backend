from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
import jwt

# ==========================================
# 1. CONFIGURATION & SECURITY SETUP
# ==========================================
DATABASE_URL = "sqlite:///./instagram_backend.db"
SECRET_KEY = "SUPER_SECRET_INSTAGRAM_KEY_DONT_SHARE" # Change in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 2. MANY-TO-MANY ASSOCIATION TABLES
# ==========================================
# Follows Association (Self-referential Many-to-Many)
follows_association = Table(
    "follows",
    Base.metadata,
    Column("follower_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("followed_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
)

# Likes Association (User to Post Many-to-Many)
likes_association = Table(
    "likes",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("post_id", Integer, ForeignKey("posts.id", ondelete="CASCADE"), primary_key=True)
)

# ==========================================
# 3. SQLALCHEMY MODELS
# ==========================================
class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    bio = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    posts = relationship("PostModel", back_populates="owner", cascade="all, delete-orphan")

    comments = relationship("CommentModel", back_populates="owner", cascade="all, delete-orphan")
    
    # Many-to-many relationship for followers
    following = relationship(
        "UserModel",
        secondary=follows_association,
        primaryjoin=id == follows_association.c.follower_id,
        secondaryjoin=id == follows_association.c.followed_id,
        backref="followers"  # <--- FIXED HERE (removed the underscore)
    )

    # Posts liked by this user
    liked_posts = relationship("PostModel", secondary=likes_association, back_populates="liked_by")


class PostModel(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    image_url = Column(String, nullable=False)
    caption = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    owner = relationship("UserModel", back_populates="posts")

    comments = relationship("CommentModel", back_populates="post", cascade="all, delete-orphan")
    
    # Users who liked this post
    liked_by = relationship("UserModel", secondary=likes_association, back_populates="liked_posts")


class CommentModel(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True, index=True)
    text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    post_id = Column(Integer, ForeignKey("posts.id", ondelete="CASCADE"), nullable=False)

    # Relationships
    owner = relationship("UserModel", back_populates="comments")
    post = relationship("PostModel", back_populates="comments")


Base.metadata.create_all(bind=engine)

# ==========================================
# 4. SECURITY UTILITIES
# ==========================================
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
        
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# ==========================================
# 5. PYDANTIC SCHEMAS
# ==========================================
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    bio: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    bio: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class PostCreate(BaseModel):
    image_url: str
    caption: Optional[str] = None

class PostResponse(BaseModel):
    id: int
    image_url: str
    caption: Optional[str] = None
    created_at: datetime
    user_id: int
    like_count: int

    class Config:
        from_attributes = True

class CommentCreate(BaseModel):
    text: str

class CommentResponse(BaseModel):
    id: int
    text: str
    created_at: datetime
    user_id: int
    post_id: int
    username: str # Extra detail to easily show who commented on the UI

    class Config:
        from_attributes = True

# ==========================================
# 6. FASTAPI APPLICATION & ROUTERS
# ==========================================
app = FastAPI(title="Instagram Backend - Advanced API")

# --- AUTH ROUTES (Register & Login) ---

@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["Auth"])
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    if db.query(UserModel).filter(UserModel.username == user_in.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(UserModel).filter(UserModel.email == user_in.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
        
    hashed_pwd = get_password_hash(user_in.password)
    new_user = UserModel(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_pwd,
        bio=user_in.bio
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/login", response_model=TokenResponse, tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
        
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# --- POST ROUTES (Protected) ---

@app.post("/posts/", response_model=PostResponse, status_code=status.HTTP_201_CREATED, tags=["Posts"])
def create_post(post_in: PostCreate, current_user: UserModel = Depends(get_current_user), db: Session = Depends(get_db)):
    new_post = PostModel(**post_in.model_dump(), user_id=current_user.id)
    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    new_post.like_count = 0
    return new_post


@app.get("/posts/", response_model=List[PostResponse], tags=["Posts"])
def get_posts(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    posts = db.query(PostModel).offset(skip).limit(limit).all()
    # Inject dynamic like count for response
    for post in posts:
        post.like_count = len(post.liked_by)
    return posts


# --- SOCIAL FEATURES (Follow & Like) ---

@app.post("/users/{user_id}/follow", tags=["Social"])
def follow_user(user_id: int, current_user: UserModel = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="You cannot follow yourself")
        
    user_to_follow = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user_to_follow:
        raise HTTPException(status_code=404, detail="User to follow not found")
        
    if user_to_follow in current_user.following:
        # Unfollow logic if they already follow
        current_user.following.remove(user_to_follow)
        db.commit()
        return {"message": f"Successfully unfollowed user {user_to_follow.username}"}
        
    current_user.following.append(user_to_follow)
    db.commit()
    return {"message": f"Successfully followed user {user_to_follow.username}"}


@app.post("/posts/{post_id}/like", tags=["Social"])
def like_post(post_id: int, current_user: UserModel = Depends(get_current_user), db: Session = Depends(get_db)):
    post = db.query(PostModel).filter(PostModel.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
        
    if post in current_user.liked_posts:
        # Unlike if already liked
        current_user.liked_posts.remove(post)
        db.commit()
        return {"message": "Post unliked successfully", "likes": len(post.liked_by)}
        
    current_user.liked_posts.append(post)
    db.commit()
    return {"message": "Post liked successfully", "likes": len(post.liked_by)}

# --- COMMENT ROUTES (Protected & Public) ---

@app.post("/posts/{post_id}/comments", response_model=CommentResponse, status_code=status.HTTP_201_CREATED, tags=["Comments"])
def add_comment(post_id: int, comment_in: CommentCreate, current_user: UserModel = Depends(get_current_user), db: Session = Depends(get_db)):
    # Verify post exists
    post = db.query(PostModel).filter(PostModel.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
        
    new_comment = CommentModel(
        text=comment_in.text,
        user_id=current_user.id,
        post_id=post_id
    )
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)
    
    # Manually attach username for the response schema validation
    new_comment.username = current_user.username
    return new_comment


@app.get("/posts/{post_id}/comments", response_model=List[CommentResponse], tags=["Comments"])
def get_post_comments(post_id: int, skip: int = 0, limit: int = 20, db: Session = Depends(get_db)):
    # Verify post exists
    post = db.query(PostModel).filter(PostModel.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
        
    comments = db.query(CommentModel).filter(CommentModel.post_id == post_id).offset(skip).limit(limit).all()
    
    # Inject username dynamically for each comment item
    for comment in comments:
        comment.username = comment.owner.username
        
    return comments


@app.delete("/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Comments"])
def delete_comment(comment_id: int, current_user: UserModel = Depends(get_current_user), db: Session = Depends(get_db)):
    comment = db.query(CommentModel).filter(CommentModel.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
        
    # Authorization safeguard: Ensure the user deleting it is the one who made it
    if comment.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this comment")
        
    db.delete(comment)
    db.commit()
    return None
import json
import pathlib
from typing import List, Union
from datetime import datetime, timedelta

from fastapi import FastAPI, Response, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from sqlmodel import Session, select
from database import TrackModel, engine

from models import Track

# https://www.bugbytes.io/posts/creating-a-music-track-api-with-fastapi-in-python/

SECRET_KEY = "dce35798c0743ff82a5d209c4be1c3d25c450429fbec0bc1e633533cc83d3d38"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2a$12$YzgqYjwiDU6/3JygvarMu.ntquk.bA3DQbfFeeEEu9nxEaYFPIZwy",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "$2a$12$medPI7AQPwVmnMjxiiRyxueOY5paMXQu3/J.y0FC0.ztzi/PDtKmi",
        "disabled": True,
    },
}

# instantiate the FastAPI app
app = FastAPI()

def fake_hash_password(password: str):
    return "fakehashed" + password

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
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
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]


# create container for our data - to be loaded at app startup.
data = []

# define app start-up event
@app.on_event("startup")
async def startup_event():
    DATAFILE = pathlib.Path() / 'data' / 'tracks.json'
    # create a Session scoped to the startup event
    # Note: we can also use a context manager
    session = Session(engine)

    # check if the database is already populated
    stmt = select(TrackModel)
    result = session.exec(stmt).first()

    # Load data if there's no results
    if result is None:
        with open(DATAFILE, 'r') as f:
            tracks = json.load(f)
            for track in tracks:
                session.add(TrackModel(**track))
    
        session.commit()
    session.close()


@app.get('/tracks/', response_model=List[Track])
def tracks(token: str = Depends(oauth2_scheme)):
    return data


@app.get('/tracks/{track_id}/', response_model=Union[Track, str])
def track(track_id: int, response: Response):
    # find the track with the given ID, or None if it does not exist
    track = next(
        (track for track in data if track["id"] == track_id), None
    )
    if track is None:
        # if a track with given ID doesn't exist, set 404 code and return string
        response.status_code = 404
        return "Track not found"
    return track


@app.post("/tracks/", response_model=Track, status_code=201)
def create_track(track: Track):
    track_dict = track.dict()
    
    # assign track next sequential ID
    track_dict['id'] = max(data, key=lambda x: x['id']).get('id') + 1
    
    # append the track to our data and return 201 response with created resource
    data.append(track_dict)
    return track_dict


@app.put("/tracks/{track_id}", response_model=Union[Track, str])
def update_track(track_id: int, updated_track: Track, response: Response):

    track = next(
        (track for track in data if track["id"] == track_id), None
    )

    if track is None:
        # if a track with given ID doesn't exist, set 404 code and return string
        response.status_code = 404
        return "Track not found"
    
    # update the track data
    for key, val in updated_track.dict().items():
        if key != 'id': # don't reset the ID
            track[key] = val
    return track


@app.delete("/tracks/{track_id}")
def delete_track(track_id: int, response: Response):

    # get the index of the track to delete
    delete_index = next(
        (idx for idx, track in enumerate(data) if track["id"] == track_id), None
    )

    if delete_index is None:
        # if a track with given ID doesn't exist, set 404 code and return string
        response.status_code = 404
        return "Track not found"
    
    # delete the track from the data, and return empty 200 response
    del data[delete_index]
    return Response(status_code=200)
import json
import pathlib
from typing import List, Union

from fastapi import FastAPI, Response, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from models import Track

# https://www.bugbytes.io/posts/creating-a-music-track-api-with-fastapi-in-python/

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

# instantiate the FastAPI app
app = FastAPI()

def fake_hash_password(password: str):
    return "fakehashed" + password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# create container for our data - to be loaded at app startup.
data = []

# define app start-up event
@app.on_event("startup")
async def startup_event():
    DATAFILE = pathlib.Path() / 'data' / 'tracks.json'
    with open(DATAFILE, 'r') as f:
        tracks = json.load(f)
        for track in tracks:
            data.append(Track(**track).dict())


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
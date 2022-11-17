import json
import pathlib
from typing import List, Union

from fastapi import FastAPI, Response

from models import Track

# instantiate the FastAPI app
app = FastAPI()

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
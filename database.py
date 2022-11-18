from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel, create_engine

# There should be one engine for the entire application
DB_FILE = 'db.sqlite3'
engine = create_engine(f"sqlite:///{DB_FILE}", echo=True)

class TrackModel(SQLModel, table=True):
    # Note: Optional fields are marked as Nullable in the database
    __tablename__ = 'track'
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    artist: str
    duration: float
    last_play: datetime


def create_tables():
    """Create the tables registered with SQLModel.metadata (i.e classes with table=True).
    More info: https://sqlmodel.tiangolo.com/tutorial/create-db-and-table/#sqlmodel-metadata
    """
    SQLModel.metadata.create_all(engine)

if __name__ == '__main__':
    # creates the table if this file is run independently, as a script
    create_tables()

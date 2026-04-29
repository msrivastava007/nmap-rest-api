import shutil
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app

TEST_DATABASE_URL = "sqlite:///./test_nmap.db"


@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    # Stub shutil.which so the startup nmap check passes in CI / dev environments
    # without nmap installed. Actual nmap calls are mocked per-test in test_routes.py.
    _real_which = shutil.which
    with patch("app.main.shutil.which", side_effect=lambda name: "/usr/bin/nmap" if name == "nmap" else _real_which(name)):
        with TestClient(app) as c:
            yield c
    app.dependency_overrides.clear()

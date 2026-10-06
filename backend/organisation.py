"""
The organisation this platform instance belongs to (Task 1).

Until Task 8 adds users and sign-in there is exactly one organisation; the
API says "the organisation" rather than taking an id, and Task 8 will scope
it to the signed-in user without changing what the pages call.
"""
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.bootstrap import DEFAULT_ORG_SLUG
from db.models import Organisation
from db.session import get_session

router = APIRouter(prefix="/api/organisation", tags=["organisation"])


class OrganisationOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class OrganisationUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)

    @field_validator("name")
    @classmethod
    def not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v


def current_organisation(session: Session) -> Organisation:
    org = session.scalar(select(Organisation).where(Organisation.slug == DEFAULT_ORG_SLUG))
    if org is None:  # init_database() creates it at start-up
        raise HTTPException(status_code=503, detail="Default organisation is not initialised yet.")
    return org


@router.get("", response_model=OrganisationOut)
def get_organisation(session: Session = Depends(get_session)) -> Organisation:
    return current_organisation(session)


@router.patch("", response_model=OrganisationOut)
def rename_organisation(body: OrganisationUpdate, session: Session = Depends(get_session)) -> Organisation:
    org = current_organisation(session)
    org.name = body.name
    session.commit()
    session.refresh(org)
    return org

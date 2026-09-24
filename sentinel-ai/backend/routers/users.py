"""
backend/routers/users.py
==========================
User management API domain (admin only).

GET    /api/users       List all users
POST   /api/users       Create a user
DELETE /api/users/{id}  Deactivate a user
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from backend.auth.service import hash_password
from backend.dependencies import AdminUser, DBSession
from backend.schemas.settings import CreateUserRequest, UserResponse

router = APIRouter()


@router.get("", response_model=list[UserResponse], summary="List all users (admin only)")
async def list_users(current_user: AdminUser, db: DBSession) -> list[UserResponse]:
    from database.repositories.user_repo import list_users as _list
    users = await _list(db)
    return [UserResponse(**u) for u in users]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED,
             summary="Create a user (admin only)")
async def create_user(
    body: CreateUserRequest,
    current_user: AdminUser,
    db: DBSession,
) -> UserResponse:
    from database.repositories.user_repo import get_user_by_email, create_user as _create
    existing = await get_user_by_email(db, body.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
    user = await _create(db, email=body.email, hashed_pw=hash_password(body.password), role=body.role)
    return UserResponse(**user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Deactivate a user (admin only)")
async def deactivate_user(
    user_id: UUID,
    current_user: AdminUser,
    db: DBSession,
) -> None:
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    from database.repositories.user_repo import get_user_by_id, deactivate_user as _deact
    if not await get_user_by_id(db, user_id):
        raise HTTPException(status_code=404, detail="User not found")
    await _deact(db, user_id)

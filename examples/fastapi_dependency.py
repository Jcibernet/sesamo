"""Sésamo reference client for FastAPI.

A single dependency that introspects the session cookie against Sésamo's
/v1/introspect endpoint. No SDK, no JWT parsing — one HTTP call per
request (p99 ~4ms locally), cached connections via httpx.

Env:
    SESAMO_URL=http://localhost:7777
    SESAMO_SERVICE_TOKEN=<your SESAMO_SERVICE_TOKEN>

Usage:
    @app.get("/me")
    async def me(user: dict = Depends(current_user)):
        return user
"""

import os

import httpx
from fastapi import Cookie, Depends, FastAPI, HTTPException

SESAMO_URL = os.environ["SESAMO_URL"]
SERVICE_TOKEN = os.environ["SESAMO_SERVICE_TOKEN"]

app = FastAPI()
_client = httpx.AsyncClient(timeout=2.0)


async def current_user(sid: str | None = Cookie(default=None)) -> dict:
    if not sid:
        raise HTTPException(status_code=401, detail="no session")
    res = await _client.post(
        f"{SESAMO_URL}/v1/introspect",
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        data={"token": sid},
    )
    session = res.json()
    if not session.get("active"):
        raise HTTPException(status_code=401, detail="invalid session")
    return session


@app.get("/me")
async def me(user: dict = Depends(current_user)) -> dict:
    return {"id": user["user_id"], "email": user["email"]}

import json
import logging
import os

import msal

from config import settings
from models import AuthStatus

logger = logging.getLogger(__name__)

_msal_app: msal.PublicClientApplication | None = None
_token_cache = msal.SerializableTokenCache()


def _load_cache() -> None:
    if os.path.exists(settings.token_cache_file):
        try:
            with open(settings.token_cache_file, "r") as f:
                _token_cache.deserialize(f.read())
        except Exception:
            logger.warning("Failed to load token cache, starting fresh")


def _save_cache() -> None:
    if _token_cache.has_state_changed:
        try:
            with open(settings.token_cache_file, "w") as f:
                f.write(_token_cache.serialize())
        except Exception:
            logger.warning("Failed to save token cache")


def _get_app() -> msal.PublicClientApplication:
    global _msal_app
    if _msal_app is None:
        _load_cache()
        _msal_app = msal.PublicClientApplication(
            client_id=settings.client_id,
            authority=settings.authority,
            token_cache=_token_cache,
        )
    return _msal_app


def initiate_auth() -> AuthStatus:
    app = _get_app()
    result = app.acquire_token_interactive(
        scopes=settings.scopes,
        prompt="select_account",
    )
    _save_cache()

    if "access_token" in result:
        claims = result.get("id_token_claims", {})
        return AuthStatus(
            is_authenticated=True,
            user_name=claims.get("preferred_username") or claims.get("name"),
            tenant_id=claims.get("tid"),
        )

    error = result.get("error_description", result.get("error", "Unknown error"))
    logger.error("Auth failed: %s", error)
    return AuthStatus(is_authenticated=False)


def get_token() -> str | None:
    app = _get_app()
    accounts = app.get_accounts()
    if not accounts:
        return None

    result = app.acquire_token_silent(
        scopes=settings.scopes,
        account=accounts[0],
    )
    _save_cache()

    if result and "access_token" in result:
        return result["access_token"]

    logger.warning("Silent token acquisition failed, interactive login required")
    return None


def get_auth_status() -> AuthStatus:
    app = _get_app()
    accounts = app.get_accounts()
    if not accounts:
        return AuthStatus(is_authenticated=False)

    account = accounts[0]
    # Try to get a token silently to verify the session is still valid
    result = app.acquire_token_silent(
        scopes=settings.scopes,
        account=account,
    )
    _save_cache()

    if result and "access_token" in result:
        claims = result.get("id_token_claims", {})
        return AuthStatus(
            is_authenticated=True,
            user_name=account.get("username") or claims.get("preferred_username"),
            tenant_id=claims.get("tid") or account.get("home_account_id", "").split(".")[-1] or None,
        )

    return AuthStatus(is_authenticated=False)


def logout() -> None:
    global _msal_app
    app = _get_app()
    accounts = app.get_accounts()
    for account in accounts:
        app.remove_account(account)
    _save_cache()

    # Also remove the cache file
    if os.path.exists(settings.token_cache_file):
        try:
            os.remove(settings.token_cache_file)
        except Exception:
            logger.warning("Failed to remove token cache file")

    _msal_app = None

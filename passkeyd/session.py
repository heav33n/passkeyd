"""Bitwarden session token stored in the desktop keyring (Secret Service)."""
import logging

import secretstorage

log = logging.getLogger(__name__)

ATTRS = {"application": "passkeyd"}
LABEL = "passkeyd Bitwarden session"


def load_session() -> str | None:
    try:
        conn = secretstorage.dbus_init()
        col = secretstorage.get_default_collection(conn)
        if col.is_locked():
            log.warning("keyring is locked")
            return None
        for it in col.search_items(ATTRS):
            return it.get_secret().decode()
    except Exception as e:
        log.warning("could not read keyring: %s", type(e).__name__)
    return None


def save_session(token: str) -> None:
    conn = secretstorage.dbus_init()
    col = secretstorage.get_default_collection(conn)
    if col.is_locked():
        col.unlock()
    col.create_item(LABEL, ATTRS, token.encode(), replace=True)

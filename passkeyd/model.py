"""Shared types between the authenticator, vault and approver."""
import threading
from dataclasses import dataclass, field
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


@dataclass
class Credential:
    rp_id: str
    credential_id: bytes
    private_key: EllipticCurvePrivateKey = field(repr=False)
    user_handle: bytes
    user_name: str
    display_name: str
    item_name: str
    created: str
    counter: int


class Cancelled(Exception):
    """The requesting app cancelled while we were waiting for the user."""


class VaultLike(Protocol):
    def find(self, rp_id: str, allow: set[bytes]) -> list[Credential]: ...


class ApproverLike(Protocol):
    def pick(self, rp_id: str, creds: list[Credential],
             cancel: threading.Event) -> Credential | None: ...

    def verify(self, rp_id: str, cred: Credential, cancel: threading.Event) -> bool: ...

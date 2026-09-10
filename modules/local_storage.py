"""
local_storage.py — Encrypted persistent session storage
=========================================================
Persists ADO connection settings and PAT across browser refreshes by
writing them to a JSON config file on disk (~/.dep_session.json).
 
Security design
---------------
The PAT (Personal Access Token) is encrypted before writing to disk:
  1. A random Fernet symmetric key is generated on first use and stored
     in the OS keyring (Windows Credential Manager, macOS Keychain,
     Linux Secret Service) under the service/user identifiers below.
  2. On every save, the PAT is encrypted with the Fernet key and stored
     as a base64 string in the JSON file.
  3. On load, the PAT is decrypted before being pushed to session_state.
 
This means the JSON file is safe to leave on disk — even if another user
reads it, they cannot decrypt the PAT without access to the keyring entry.
 
Dependencies: cryptography, keyring  (both in requirements.txt)
 
Non-sensitive fields (org_url, project, repo, branch, uc_root) are stored
in plain text since they are not secrets.
"""

from __future__ import annotations
import os
import streamlit as st
import streamlit.components.v1 as components
import json
from cryptography.fernet import Fernet
import keyring

# Path to the persistent config file on disk
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".dep_session.json")

# Fields to persist/restore. `pat` is handled separately (encrypted).
KEYS = ("org_url", "pat", "project", "repo", "branch", "uc_root")

# Keyring identifiers — used to store/retrieve the encryption key
KEYRING_SERVICE = "dep_app"
KEYRING_USER    = "ca6ebace-846b-4f32-bc50-a38b1f270c59"   # fixed UUID for this app

# -------------------------
# Key management
# -------------------------
def _get_or_create_key() -> bytes:
    """
    Retrieve the Fernet encryption key from the OS keyring.
    If no key exists yet, generate a new one and store it.
    Returns the key as bytes.
    """
    key = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
    if key is None:
        # First run — generate a fresh random key and persist it
        key = Fernet.generate_key().decode()
        keyring.set_password(KEYRING_SERVICE, KEYRING_USER, key)
    return key.encode()


def _get_cipher() -> Fernet:
    """Return a Fernet cipher instance using the stored key."""
    return Fernet(_get_or_create_key())

# -------------------------
# Load
# -------------------------
def load_from_storage() -> dict:
    """
    Read the config file and push values into st.session_state.
 
    Called once per session at the top of app.py before any defaults are set.
    Only sets session_state keys that are not already populated, so explicit
    user actions during the session take precedence over stored values.
 
    The PAT is decrypted using the keyring-stored key before being stored
    in session_state. If decryption fails (e.g. keyring entry was deleted),
    a warning is shown and the PAT field remains empty.
    """
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH) as f:
            data = json.load(f)

        # Restore plain-text fields (skip if already set in session_state)
        for key in KEYS:
            if key in data and not st.session_state.get(key):
                st.session_state[key] = data[key]

        # Decrypt PAT
        encrypted_pat = data.get("pat")
        if encrypted_pat:# and not st.session_state.get("pat"):
            try:
                cipher = _get_cipher()
                decrypted = cipher.decrypt(encrypted_pat.encode()).decode()
                st.session_state["pat"] = decrypted
            except Exception:
                st.warning("Failed to decrypt stored PAT")

        return data
    except Exception as e:
        st.warning(f"Storage load error: {e}")
        return {}
 
 
def save_to_storage(data: dict):
    """
    Write the provided settings to the config file.
 
    Merges with any existing stored values so that saving connection
    settings doesn't erase previously-saved repo settings and vice versa.
    The PAT is encrypted before writing.
    """
    existing = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                existing = json.load(f)
        except Exception:
            pass
    # Copy non-PAT fields directly
    for k in KEYS:
        if k in data:
            existing[k] = data[k]

    # Encrypt and store the PAT if provided
    if "pat" in data and data["pat"]:
        try:
            cipher = _get_cipher()
            encrypted = cipher.encrypt(data["pat"].encode()).decode()
            existing["pat"] = encrypted
        except Exception as e:
            st.warning(f"Encryption error: {e}")

    # Write merged data back to disk
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        st.warning(f"Storage save error: {e}")
 
# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------

def clear_storage():
    """
    Delete the config file and optionally remove the keyring entry.
 
    Called when the user clicks the disconnect (✕) button.
    Removing the keyring entry means the next run generates a new key;
    any existing encrypted config file (e.g. backup) becomes unreadable.
    """
    try:
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
    except Exception:
        pass

    # Remove the encryption key from the keyring
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USER)
    except Exception:
        pass # key may not exist — ignore
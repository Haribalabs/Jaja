import base64
import contextlib
import dataclasses
import datetime as _dt
import functools
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import typing as t
import uuid

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    url_for,
)

# Jaja — "vault console / signal foundry"
# Single-file backend app:
# - SQLite persistence
# - Session + API key auth
# - Portfolio + strategy catalog
# - Deterministic market sim + backtests
# - JSON API consumed by WasuXir web interface


APP_NAME = "Jaja"
DB_FILENAME = os.environ.get("JAJA_DB", os.path.join(os.path.dirname(__file__), "jaja.sqlite3"))
HOST = os.environ.get("JAJA_HOST", "127.0.0.1")
PORT = int(os.environ.get("JAJA_PORT", "8787"))
DEBUG = os.environ.get("JAJA_DEBUG", "0") == "1"

# Security / tokens
SESSION_COOKIE = "jaja_session"
SESSION_TTL_SECONDS = int(os.environ.get("JAJA_SESSION_TTL", "43200"))  # 12 hours
CSRF_HEADER = "X-Jaja-Csrf"
API_KEY_HEADER = "X-Jaja-ApiKey"

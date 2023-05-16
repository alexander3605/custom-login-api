#!/bin/sh
set -eu

uvicorn custom_login_api.app.main:app --reload --port 8000

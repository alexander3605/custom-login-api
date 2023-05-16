#!/bin/sh

# Define base image.
FROM python:3.10-buster

# Copy project files.
RUN mkdir build
WORKDIR /build
COPY . .

# Install Poetry (dependency manager)
ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=off \
  PIP_NO_CACHE_DIR=off \
  POETRY_VERSION=1.4.2 \
  POETRY_VIRTUALENVS_CREATE=false \
  PATH="${PATH}:/root/.local/bin"
RUN curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies.
RUN poetry install --no-interaction --no-root --no-ansi --only main

# Expose port.
EXPOSE 8000/tcp

# Define execution entrypoint.
CMD python -m uvicorn custom_login_api.app.main:app --host 0.0.0.0 --port 8000

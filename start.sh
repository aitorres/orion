#!/bin/bash

echo "Preparing Orion..."
uv run ./manage.py migrate --no-input
uv run ./manage.py collectstatic --no-input

echo "Starting Orion!"
uv run gunicorn -w 2 -b 0.0.0.0:8080 orion.wsgi

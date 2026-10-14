#!/usr/bin/env python3
"""ApacheWatch command-line entry point and WSGI application."""

from apachewatch_app import create_app
from apachewatch_app.cli import main

app = create_app()
config = app.config["APACHEWATCH"]


if __name__ == "__main__":
    main(app)

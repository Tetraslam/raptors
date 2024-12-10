from http.server import BaseHTTPRequestHandler
from backend.app.main import app
import os

def handler(request, response):
    return app(request, response)

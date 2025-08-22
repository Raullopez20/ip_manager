#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WSGI entry point para IIS con HttpPlatformHandler
"""

import sys
import os

# Agregar el directorio de la aplicación al path
sys.path.insert(0, os.path.dirname(__file__))

from app import app

if __name__ == "__main__":
    # Obtener el puerto del entorno (asignado por IIS)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=False)

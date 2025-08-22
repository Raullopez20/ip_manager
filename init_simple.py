#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script alternativo de inicialización para IP Manager
Para usar en caso de problemas de compatibilidad
"""

import os
import sys

# Añadir el directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db, User, Category, Application, UserFavorite

    def create_database():
        """Crear base de datos y tablas"""
        with app.app_context():
            print("Creando tablas...")
            db.create_all()

            # Verificar si ya hay datos
            if User.query.count() > 0:
                print("La base de datos ya contiene datos.")
                return

            print("Creando datos de ejemplo...")

            # Crear categorías
            categories = [
                Category(name='Servidores', description='Servidores de aplicaciones', color='#dc3545', icon='fa-server'),
                Category(name='Bases de Datos', description='Sistemas de BD', color='#28a745', icon='fa-database'),
                Category(name='Redes', description='Equipos de red', color='#007bff', icon='fa-network-wired'),
                Category(name='Desarrollo', description='Herramientas dev', color='#6f42c1', icon='fa-code'),
                Category(name='Monitoreo', description='Sistemas de monitoreo', color='#fd7e14', icon='fa-chart-line'),
            ]

            for cat in categories:
                db.session.add(cat)
            db.session.commit()

            # Crear usuario admin
            admin = User(
                username='admin',
                email='admin@empresa.com',
                full_name='Administrador del Sistema',
                department='IT',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)

            # Crear usuarios normales
            users_data = [
                {'username': 'juan.perez', 'email': 'juan@empresa.com', 'full_name': 'Juan Pérez', 'department': 'IT'},
                {'username': 'maria.garcia', 'email': 'maria@empresa.com', 'full_name': 'María García', 'department': 'Ventas'},
            ]

            for user_data in users_data:
                user = User(**user_data)
                user.set_password('usuario123')
                db.session.add(user)

            db.session.commit()

            # Crear aplicaciones de ejemplo
            apps_data = [
                {
                    'name': 'Panel Control',
                    'description': 'Panel principal del servidor',
                    'ip_address': '192.168.1.100',
                    'port': 8080,
                    'protocol': 'https',
                    'category_id': categories[0].id,
                    'tags': 'admin,control'
                },
                {
                    'name': 'Base de Datos',
                    'description': 'PhpMyAdmin',
                    'ip_address': '192.168.1.101',
                    'port': 3306,
                    'protocol': 'https',
                    'category_id': categories[1].id,
                    'tags': 'mysql,database'
                },
                {
                    'name': 'Router',
                    'description': 'Router principal',
                    'ip_address': '192.168.1.1',
                    'port': 80,
                    'protocol': 'http',
                    'category_id': categories[2].id,
                    'tags': 'router,network'
                }
            ]

            for app_data in apps_data:
                app = Application(**app_data)
                db.session.add(app)

            db.session.commit()

            print("\n=== BASE DE DATOS INICIALIZADA ===")
            print("Usuarios creados:")
            print("- admin / admin123 (Administrador)")
            print("- juan.perez / usuario123")
            print("- maria.garcia / usuario123")
            print("\nAplicación lista en http://127.0.0.1:5000")

    if __name__ == '__main__':
        create_database()

except ImportError as e:
    print(f"Error de importación: {e}")
    print("\nPor favor, instala las dependencias:")
    print("pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

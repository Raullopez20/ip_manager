#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de inicialización para la aplicación de gestión de enlaces IP
Crea datos de ejemplo y configura la base de datos inicial
"""

from app import app, db, User, Category, Application, UserFavorite, UserApplicationPermission
from datetime import datetime

def init_database():
    global app  # Asegura que se usa la importación global
    with app.app_context():
        # Crear todas las tablas
        print("Creando tablas en la base de datos...")
        db.create_all()

        # Verificar si ya hay datos
        if User.query.count() > 0:
            print("La base de datos ya contiene datos. Abortando inicialización.")
            return

        print("Inicializando base de datos con datos de ejemplo...")

        # Crear categorías
        categories_data = [
            {'name': 'Servidores', 'description': 'Servidores de aplicaciones y servicios', 'color': '#dc3545', 'icon': 'fa-server'},
            {'name': 'Bases de Datos', 'description': 'Sistemas de gestión de bases de datos', 'color': '#28a745', 'icon': 'fa-database'},
            {'name': 'Redes', 'description': 'Equipos de red y monitoreo', 'color': '#007bff', 'icon': 'fa-network-wired'},
            {'name': 'Desarrollo', 'description': 'Herramientas de desarrollo', 'color': '#6f42c1', 'icon': 'fa-code'},
            {'name': 'Monitoreo', 'description': 'Sistemas de monitoreo y métricas', 'color': '#fd7e14', 'icon': 'fa-chart-line'},
            {'name': 'Seguridad', 'description': 'Herramientas de seguridad', 'color': '#e83e8c', 'icon': 'fa-shield-alt'},
        ]

        categories = []
        for cat_data in categories_data:
            category = Category(**cat_data)
            db.session.add(category)
            categories.append(category)

        db.session.commit()
        print(f"Creadas {len(categories)} categorías")

        # Crear usuario administrador
        admin = User(
            username='admin',
            email='admin@empresa.com',
            full_name='Administrador del Sistema',
            department='IT',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)

        # Crear usuarios de ejemplo
        users_data = [
            {'username': 'juan.perez', 'email': 'juan.perez@empresa.com', 'full_name': 'Juan Pérez', 'department': 'IT', 'password': 'usuario123'},
            {'username': 'maria.garcia', 'email': 'maria.garcia@empresa.com', 'full_name': 'María García', 'department': 'Ventas', 'password': 'usuario123'},
            {'username': 'carlos.lopez', 'email': 'carlos.lopez@empresa.com', 'full_name': 'Carlos López', 'department': 'RRHH', 'password': 'usuario123'},
            {'username': 'ana.martinez', 'email': 'ana.martinez@empresa.com', 'full_name': 'Ana Martínez', 'department': 'Contabilidad', 'password': 'usuario123'},
        ]

        users = [admin]
        for user_data in users_data:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                full_name=user_data['full_name'],
                department=user_data['department'],
                is_admin=False
            )
            user.set_password(user_data['password'])
            db.session.add(user)
            users.append(user)

        db.session.commit()
        print(f"Creados {len(users)} usuarios")

        # Crear aplicaciones de ejemplo
        applications_data = [
            {
                'name': 'Panel de Control Principal',
                'description': 'Panel de administración del servidor principal',
                'ip_address': '192.168.1.100',
                'port': 8080,
                'protocol': 'https',
                'url_path': '/admin',
                'category_id': categories[0].id,
                'tags': 'admin, control, servidor'
            },
            {
                'name': 'Base de Datos MySQL',
                'description': 'PhpMyAdmin para gestión de BD',
                'ip_address': '192.168.1.101',
                'port': 3306,
                'protocol': 'https',
                'url_path': '/phpmyadmin',
                'category_id': categories[1].id,
                'tags': 'mysql, database, phpmyadmin'
            },
            {
                'name': 'Router Principal',
                'description': 'Interfaz web del router principal',
                'ip_address': '192.168.1.1',
                'port': 80,
                'protocol': 'http',
                'url_path': '/',
                'category_id': categories[2].id,
                'tags': 'router, network, config'
            },
            {
                'name': 'GitLab Interno',
                'description': 'Repositorio de código de la empresa',
                'ip_address': '192.168.1.102',
                'port': 443,
                'protocol': 'https',
                'url_path': '/',
                'category_id': categories[3].id,
                'tags': 'git, código, desarrollo'
            },
            {
                'name': 'Jenkins CI/CD',
                'description': 'Sistema de integración continua',
                'ip_address': '192.168.1.103',
                'port': 8080,
                'protocol': 'https',
                'url_path': '/',
                'category_id': categories[3].id,
                'tags': 'jenkins, ci, cd, build'
            },
            {
                'name': 'Grafana Monitoring',
                'description': 'Dashboard de métricas y monitoreo',
                'ip_address': '192.168.1.104',
                'port': 3000,
                'protocol': 'https',
                'url_path': '/',
                'category_id': categories[4].id,
                'tags': 'grafana, monitoring, metrics'
            },
            {
                'name': 'Firewall Management',
                'description': 'Panel de gestión del firewall',
                'ip_address': '192.168.1.105',
                'port': 443,
                'protocol': 'https',
                'url_path': '/admin',
                'category_id': categories[5].id,
                'tags': 'firewall, security, admin'
            },
            {
                'name': 'File Server',
                'description': 'Servidor de archivos compartidos',
                'ip_address': '192.168.1.106',
                'port': 445,
                'protocol': 'smb',
                'url_path': '/shared',
                'category_id': categories[0].id,
                'tags': 'files, storage, smb'
            }
        ]

        applications = []
        for app_data in applications_data:
            application = Application(**app_data)
            db.session.add(application)
            applications.append(application)

        db.session.commit()
        print(f"Creadas {len(applications)} aplicaciones")

        # Crear algunos favoritos de ejemplo
        # El admin tiene acceso a todo
        for app in applications[:4]:
            favorite = UserFavorite(user_id=admin.id, application_id=app.id)
            db.session.add(favorite)

        # Usuario regular tiene acceso limitado
        user_apps = [applications[0], applications[2], applications[3]]  # Panel, Router, GitLab
        for i, app in enumerate(user_apps):
            favorite = UserFavorite(user_id=users[1].id, application_id=app.id, order_index=i)
            db.session.add(favorite)

        db.session.commit()
        print("Creados favoritos de ejemplo")

        print("\n=== BASE DE DATOS INICIALIZADA CORRECTAMENTE ===")
        print("Usuarios creados:")
        print("- admin / admin123 (Administrador)")
        print("- juan.perez / usuario123")
        print("- maria.garcia / usuario123")
        print("- carlos.lopez / usuario123")
        print("- ana.martinez / usuario123")
        print("\nAccede a http://127.0.0.1:5000 para usar la aplicación")


if __name__ == '__main__':
    init_database()

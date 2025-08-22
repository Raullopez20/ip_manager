#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de inicialización rápida para IP Manager
Crea la base de datos y datos de prueba
"""

import os
import sys

# Agregar el directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db, User, Category, Application
    from werkzeug.security import generate_password_hash

    def init_database():
        """Inicializar base de datos con datos de prueba"""
        print("🔄 Inicializando base de datos...")

        with app.app_context():
            # Crear todas las tablas
            db.create_all()
            print("✅ Tablas creadas")

            # Verificar si ya existe el admin
            if User.query.filter_by(username='admin').first():
                print("⚠️  El usuario admin ya existe")
                return

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

            # Crear usuario normal de prueba
            user_test = User(
                username='usuario',
                email='usuario@empresa.com',
                full_name='Usuario de Prueba',
                department='Ventas',
                is_admin=False
            )
            user_test.set_password('123456')
            db.session.add(user_test)

            # Crear categorías por defecto
            categories_data = [
                {'name': 'Servidores', 'description': 'Servidores de la empresa', 'color': '#dc3545', 'icon': 'fas fa-server'},
                {'name': 'Aplicaciones Web', 'description': 'Aplicaciones web internas', 'color': '#28a745', 'icon': 'fas fa-globe'},
                {'name': 'Bases de Datos', 'description': 'Sistemas de base de datos', 'color': '#007bff', 'icon': 'fas fa-database'},
                {'name': 'Monitoreo', 'description': 'Herramientas de monitoreo', 'color': '#ffc107', 'icon': 'fas fa-chart-line'},
                {'name': 'Red', 'description': 'Equipos de red', 'color': '#6c757d', 'icon': 'fas fa-network-wired'}
            ]

            categories = []
            for cat_data in categories_data:
                category = Category(**cat_data)
                db.session.add(category)
                categories.append(category)

            # Confirmar categorías primero
            db.session.commit()

            # Crear aplicaciones de ejemplo
            apps_data = [
                {
                    'name': 'Panel de Control Principal',
                    'description': 'Panel de administración del servidor principal',
                    'ip_address': '192.168.1.100',
                    'port': 8080,
                    'protocol': 'https',
                    'url_path': '/admin',
                    'category_id': categories[0].id,
                    'tags': 'admin, panel, control',
                    'is_active': True
                },
                {
                    'name': 'Base de Datos MySQL',
                    'description': 'Interfaz web de administración de MySQL',
                    'ip_address': '192.168.1.101',
                    'port': 80,
                    'protocol': 'http',
                    'url_path': '/phpmyadmin',
                    'category_id': categories[2].id,
                    'tags': 'mysql, database, admin',
                    'is_active': True
                },
                {
                    'name': 'Monitor de Red',
                    'description': 'Sistema de monitoreo de infraestructura',
                    'ip_address': '192.168.1.102',
                    'port': 3000,
                    'protocol': 'http',
                    'url_path': '/',
                    'category_id': categories[3].id,
                    'tags': 'monitor, red, grafana',
                    'is_active': True
                },
                {
                    'name': 'Router Principal',
                    'description': 'Configuración del router principal',
                    'ip_address': '192.168.1.1',
                    'port': 80,
                    'protocol': 'http',
                    'url_path': '/',
                    'category_id': categories[4].id,
                    'tags': 'router, red, config',
                    'is_active': True
                },
                {
                    'name': 'Servidor Web Apache',
                    'description': 'Panel de estado del servidor web',
                    'ip_address': '192.168.1.103',
                    'port': 80,
                    'protocol': 'http',
                    'url_path': '/server-status',
                    'category_id': categories[0].id,
                    'tags': 'apache, web, servidor',
                    'is_active': True
                }
            ]

            for app_data in apps_data:
                app_instance = Application(**app_data)
                db.session.add(app_instance)

            # Confirmar todo
            db.session.commit()

            print("✅ Datos de prueba creados:")
            print("   👤 Usuario admin: admin / admin123")
            print("   👤 Usuario normal: usuario / 123456")
            print("   📁 5 Categorías creadas")
            print("   🖥️  5 Aplicaciones de ejemplo")
            print("")
            print("🚀 ¡Listo! Ejecuta: python app.py")

    if __name__ == '__main__':
        init_database()

except ImportError as e:
    print(f"❌ Error: {e}")
    print("🔧 Instala las dependencias primero:")
    print("   pip install flask flask-sqlalchemy flask-migrate pymysql werkzeug")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error inesperado: {e}")
    sys.exit(1)

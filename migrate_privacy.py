#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de migración para agregar campos de privacidad a las aplicaciones
Ejecutar después de actualizar el código para agregar los nuevos campos a la base de datos
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db

def migrate_database():
    """Ejecutar migración de base de datos"""
    print("🔄 Iniciando migración de base de datos...")

    with app.app_context():
        try:
            # SQL para agregar los nuevos campos a la tabla applications
            migration_sql = [
                # Agregar campo is_private (por defecto False para aplicaciones existentes)
                "ALTER TABLE applications ADD COLUMN is_private BOOLEAN NOT NULL DEFAULT FALSE;",

                # Agregar campo allowed_departments (puede ser NULL)
                "ALTER TABLE applications ADD COLUMN allowed_departments TEXT;",

                # Crear índice para mejorar consultas de aplicaciones privadas
                "CREATE INDEX idx_applications_is_private ON applications(is_private);",

                # Crear índice combinado para consultas de aplicaciones activas y privadas
                "CREATE INDEX idx_applications_active_private ON applications(is_active, is_private);"
            ]

            print("📝 Ejecutando comandos SQL de migración...")

            for i, sql in enumerate(migration_sql, 1):
                try:
                    print(f"   {i}. {sql[:50]}...")
                    db.session.execute(sql)
                    db.session.commit()
                    print(f"   ✅ Comando {i} ejecutado correctamente")
                except Exception as e:
                    # Si el campo ya existe, continuar
                    if "Duplicate column name" in str(e) or "already exists" in str(e):
                        print(f"   ⚠️  Campo ya existe, continuando...")
                        db.session.rollback()
                        continue
                    else:
                        print(f"   ❌ Error en comando {i}: {e}")
                        db.session.rollback()
                        raise e

            print("\n🎉 Migración completada exitosamente!")
            print("\n📊 Resumen de cambios:")
            print("   - Agregado campo 'is_private' a tabla applications")
            print("   - Agregado campo 'allowed_departments' a tabla applications")
            print("   - Creados índices para optimizar consultas")
            print("\n✨ Las aplicaciones existentes se mantienen como públicas por defecto")

        except Exception as e:
            print(f"\n❌ Error durante la migración: {e}")
            db.session.rollback()
            return False

    return True

def verify_migration():
    """Verificar que la migración se ejecutó correctamente"""
    print("\n🔍 Verificando migración...")

    with app.app_context():
        try:
            # Verificar que los campos existen
            result = db.session.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'applications' 
                AND COLUMN_NAME IN ('is_private', 'allowed_departments')
            """)

            columns = [row[0] for row in result]

            if 'is_private' in columns and 'allowed_departments' in columns:
                print("✅ Todos los campos necesarios están presentes")

                # Contar aplicaciones por tipo
                total_apps = db.session.execute("SELECT COUNT(*) FROM applications").scalar()
                private_apps = db.session.execute("SELECT COUNT(*) FROM applications WHERE is_private = TRUE").scalar()
                public_apps = total_apps - private_apps

                print(f"📈 Estadísticas actuales:")
                print(f"   - Total de aplicaciones: {total_apps}")
                print(f"   - Aplicaciones públicas: {public_apps}")
                print(f"   - Aplicaciones privadas: {private_apps}")

                return True
            else:
                print(f"❌ Faltan campos: {set(['is_private', 'allowed_departments']) - set(columns)}")
                return False

        except Exception as e:
            print(f"❌ Error verificando migración: {e}")
            return False

if __name__ == '__main__':
    print("🚀 Migración de Base de Datos - IP Manager")
    print("=" * 50)

    # Ejecutar migración
    if migrate_database():
        # Verificar migración
        if verify_migration():
            print("\n🎊 ¡Migración completada y verificada exitosamente!")
            print("\n📋 Próximos pasos:")
            print("   1. Reinicia la aplicación Flask")
            print("   2. Accede como administrador")
            print("   3. Ve a 'Aplicaciones' > 'Gestionar Permisos'")
            print("   4. Configura las aplicaciones como privadas según necesites")
            print("\n💡 Tip: Las aplicaciones existentes permanecen públicas hasta que las configures como privadas")
        else:
            print("\n⚠️  Migración ejecutada pero con problemas en la verificación")
            sys.exit(1)
    else:
        print("\n💥 Migración falló")
        sys.exit(1)

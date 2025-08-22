#!/usr/bin/env python3
"""
Script para corregir los iconos de FontAwesome en la base de datos
"""

import sqlite3
import os

def fix_fontawesome_icons():
    """Corrige los iconos de FontAwesome agregando el prefijo 'fas' donde sea necesario"""

    # Conectar a la base de datos
    db_path = 'ip_manager.db'
    if not os.path.exists(db_path):
        print("❌ No se encontró la base de datos ip_manager.db")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Obtener todas las categorías
        cursor.execute("SELECT id, name, icon FROM categories")
        categories = cursor.fetchall()

        print("🔧 Corrigiendo iconos de categorías...")

        for category_id, name, icon in categories:
            # Si el icono no tiene prefijo, agregar 'fas'
            if icon and not any(icon.startswith(prefix) for prefix in ['fas ', 'far ', 'fab ', 'fal ', 'fad ']):
                new_icon = f"fas {icon}"
                cursor.execute("UPDATE categories SET icon = ? WHERE id = ?", (new_icon, category_id))
                print(f"  ✅ {name}: '{icon}' → '{new_icon}'")
            else:
                print(f"  ➡️  {name}: '{icon}' (ya tiene prefijo correcto)")

        # Confirmar cambios
        conn.commit()
        print("\n✅ Todos los iconos han sido corregidos exitosamente!")

        # Mostrar el resultado final
        print("\n📋 Estado final de las categorías:")
        cursor.execute("SELECT name, icon FROM categories ORDER BY name")
        for name, icon in cursor.fetchall():
            print(f"  • {name}: {icon}")

    except Exception as e:
        print(f"❌ Error al corregir los iconos: {e}")
        conn.rollback()

    finally:
        conn.close()

if __name__ == "__main__":
    fix_fontawesome_icons()

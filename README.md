# 🌐 Gestor de Enlaces IP Empresariales

Sistema completo para gestionar y acceder a enlaces IP internos de la empresa de forma organizada y segura.

## 🚀 Características Principales

### 👤 **Para Usuarios**
- **Dashboard personalizado** con aplicaciones favoritas
- **Búsqueda avanzada** por nombre, IP, categoría o etiquetas
- **Sistema de favoritos** personalizable
- **Acceso directo** a aplicaciones con un clic
- **Historial de accesos** recientes
- **Interfaz responsive** para móviles y tablets

### 🔧 **Para Administradores**
- **Panel de administración completo**
- **Gestión de usuarios** con roles y permisos
- **Gestión de aplicaciones** con iconos personalizados
- **Sistema de categorías** organizativo
- **Auditoría completa** de accesos y movimientos
- **Estadísticas detalladas** de uso
- **Exportación de logs** para análisis

### 🔒 **Seguridad**
- **Contraseñas cifradas** con hash bcrypt
- **Sesiones seguras** con Flask-Session
- **Control de acceso** basado en roles
- **Auditoría completa** de todas las acciones
- **Validación de permisos** en tiempo real

## 📋 Requisitos

- Python 3.8 o superior
- MySQL 5.7 o superior
- Navegador web moderno

## 🛠️ Instalación

### 1. Clonar/Descargar el proyecto
```bash
cd ip_manager
```

### 2. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 3. Configurar la base de datos
1. Crear base de datos MySQL:
```sql
CREATE DATABASE ip_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

2. Actualizar configuración en `app.py` si es necesario:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://usuario:contraseña@servidor:puerto/ip_manager'
```

### 4. Inicializar la base de datos
```bash
python init_db.py
```

### 5. Ejecutar la aplicación
```bash
python app.py
```

La aplicación estará disponible en: http://localhost:5001

## 🔑 Credenciales Iniciales

### Administrador
- **Usuario:** `admin`
- **Contraseña:** `admin123`

### Usuarios de ejemplo
- `juan.perez` / `usuario123` (IT)
- `maria.garcia` / `usuario123` (Ventas)
- `carlos.lopez` / `usuario123` (RRHH)
- `ana.martinez` / `usuario123` (Contabilidad)

**⚠️ IMPORTANTE:** Cambia las contraseñas por defecto después de la primera instalación.

## 📁 Estructura del Proyecto

```
ip_manager/
├── app.py                      # Aplicación principal
├── init_db.py                  # Script de inicialización
├── requirements.txt            # Dependencias
├── README.md                   # Este archivo
├── static/
│   ├── css/
│   │   └── style.css          # Estilos personalizados
│   ├── js/
│   │   └── app.js             # JavaScript principal
│   ├── img/
│   │   └── default-app-icon.png
│   └── app_icons/             # Iconos de aplicaciones
├── templates/
│   ├── base.html              # Plantilla base
│   ├── login.html             # Página de login
│   ├── dashboard.html         # Dashboard principal
│   ├── browse.html            # Explorar aplicaciones
│   ├── search.html            # Búsqueda avanzada
│   ├── admin/
│   │   ├── dashboard.html     # Panel admin
│   │   ├── users.html         # Gestión usuarios
│   │   ├── create_user.html   # Crear usuario
│   │   ├── applications.html  # Gestión apps
│   │   ├── create_application.html
│   │   └── logs.html          # Auditoría
│   └── errors/
│       ├── 403.html
│       ├── 404.html
│       └── 500.html
```

## 🎯 Uso del Sistema

### Para Usuarios Normales

1. **Login:** Accede con tu usuario y contraseña
2. **Dashboard:** Ve tus aplicaciones favoritas y recientes
3. **Explorar:** Busca nuevas aplicaciones por categoría
4. **Favoritos:** Agrega aplicaciones frecuentes a favoritos
5. **Acceso:** Haz clic en cualquier aplicación para acceder

### Para Administradores

1. **Panel Admin:** Accede desde el menú "Administración"
2. **Usuarios:** Crea, edita y gestiona usuarios
3. **Aplicaciones:** Agrega nuevas aplicaciones IP
4. **Categorías:** Organiza las aplicaciones
5. **Auditoría:** Revisa logs de acceso y actividad

## 📊 Funcionalidades Destacadas

### 🎨 **Gestión de Aplicaciones**
- Agrega aplicaciones con IP, puerto y protocolo
- Sube iconos personalizados
- Organiza por categorías con colores
- Etiquetas para búsqueda avanzada
- Control de estado activo/inactivo

### 👥 **Gestión de Usuarios**
- Creación de usuarios con departamentos
- Roles: Usuario normal y Administrador
- Control de estado activo/inactivo
- Historial de último login

### 🔍 **Sistema de Búsqueda**
- Búsqueda por nombre, descripción, IP
- Filtros por categoría y etiquetas
- Búsqueda en tiempo real
- Resultados paginados

### 📈 **Auditoría y Estadísticas**
- Log de todos los accesos
- Estadísticas de uso por aplicación
- Usuarios más activos
- Filtros de auditoría avanzados
- Exportación de datos

## 🔧 Configuración Avanzada

### Variables de Entorno
```bash
export SECRET_KEY="tu-clave-secreta-produccion"
export DATABASE_URL="mysql+pymysql://user:pass@host:port/db"
export FLASK_ENV="production"
```

### Configuración de Producción
1. Cambiar `SECRET_KEY` en producción
2. Configurar base de datos MySQL dedicada
3. Configurar servidor web (nginx + gunicorn)
4. Habilitar HTTPS
5. Configurar backups automáticos

## 🐛 Solución de Problemas

### Error de conexión MySQL
```bash
pip install PyMySQL
```

### Error de permisos de archivos
```bash
chmod 755 static/app_icons/
```

### Error de dependencias
```bash
pip install --upgrade -r requirements.txt
```

## 🔄 Backup y Mantenimiento

### Backup de Base de Datos
```bash
mysqldump -u usuario -p ip_manager > backup_$(date +%Y%m%d).sql
```

### Limpieza de Logs Antiguos
```sql
DELETE FROM access_logs WHERE access_time < DATE_SUB(NOW(), INTERVAL 90 DAY);
```

## 🚀 Próximas Mejoras

- [ ] API REST completa
- [ ] Autenticación LDAP/Active Directory
- [ ] Notificaciones push
- [ ] Temas personalizables
- [ ] Exportación de reportes
- [ ] Integración con monitoreo
- [ ] App móvil

## 📞 Soporte

Para soporte técnico o sugerencias:
- Contacta al administrador del sistema
- Revisa los logs en el panel de administración
- Consulta la documentación de la empresa

---

**🎉 ¡Tu sistema de gestión de enlaces IP está listo para usar!**

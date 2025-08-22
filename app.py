#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aplicación de Gestión de Enlaces IP Empresariales
Sistema completo para gestionar accesos a IPs internas de la empresa
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import json
import uuid
from functools import wraps
import ipaddress

app = Flask(__name__)

# Configuración
app.config['SECRET_KEY'] = 'ip-manager-secret-key-change-in-production-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ejemplo:ejemplo@ejemplo:3306/ip_manager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'app_icons')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB para iconos

# Crear directorio para iconos si no existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)
os.makedirs('static/img', exist_ok=True)
os.makedirs('templates/admin', exist_ok=True)
os.makedirs('templates/errors', exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =============================================================================
# MODELOS DE BASE DE DATOS
# =============================================================================

class User(db.Model):
    """Modelo de Usuario"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(200), nullable=False)
    department = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # Relaciones
    favorites = db.relationship('UserFavorite', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    access_logs = db.relationship('AccessLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        """Cifrar contraseña"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verificar contraseña"""
        return check_password_hash(self.password_hash, password)

    def get_favorites(self):
        """Obtener aplicaciones favoritas del usuario"""
        return Application.query.join(UserFavorite).filter(UserFavorite.user_id == self.id).all()

    def __repr__(self):
        return f'<User {self.username}>'


class Category(db.Model):
    """Modelo de Categoría de Aplicaciones"""
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default='#007bff')  # Color hex para UI
    icon = db.Column(db.String(50), default='fa-folder')  # FontAwesome icon
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones
    applications = db.relationship('Application', backref='category', lazy='dynamic')

    def __repr__(self):
        return f'<Category {self.name}>'


class Application(db.Model):
    """Modelo de Aplicación/Enlace IP"""
    __tablename__ = 'applications'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4 o IPv6
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10), default='http')  # http, https, ssh, etc.
    url_path = db.Column(db.String(500), default='/')  # Ruta adicional en la URL
    icon_filename = db.Column(db.String(255))  # Archivo de icono personalizado
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Campos de privacidad
    is_private = db.Column(db.Boolean, default=False, nullable=False)  # Si es privada o pública
    allowed_departments = db.Column(db.Text)  # Departamentos permitidos (separados por comas)

    requires_auth = db.Column(db.Boolean, default=False)  # Si requiere autenticación adicional
    auth_username = db.Column(db.String(100))  # Usuario por defecto (opcional)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Metadatos adicionales
    tags = db.Column(db.Text)  # Tags separados por comas para búsqueda
    access_count = db.Column(db.Integer, default=0)
    last_accessed = db.Column(db.DateTime)

    # Relaciones
    favorites = db.relationship('UserFavorite', backref='application', lazy='dynamic', cascade='all, delete-orphan')
    access_logs = db.relationship('AccessLog', backref='application', lazy='dynamic', cascade='all, delete-orphan')
    permissions = db.relationship('UserApplicationPermission', backref='application', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def full_url(self):
        """Generar URL completa"""
        port_str = f':{self.port}' if self.port and self.port not in [80, 443] else ''
        return f'{self.protocol}://{self.ip_address}{port_str}{self.url_path}'

    @property
    def icon_url(self):
        """URL del icono"""
        if self.icon_filename:
            return url_for('static', filename=f'app_icons/{self.icon_filename}')
        return url_for('static', filename='img/default-app-icon.png')

    def get_tags_list(self):
        """Obtener lista de tags"""
        return [tag.strip() for tag in (self.tags or '').split(',') if tag.strip()]

    def get_allowed_departments_list(self):
        """Obtener lista de departamentos permitidos"""
        return [dept.strip() for dept in (self.allowed_departments or '').split(',') if dept.strip()]

    def can_user_access(self, user):
        """Verificar si un usuario puede acceder a esta aplicación"""
        # Si la aplicación no es privada, todos pueden acceder
        if not self.is_private:
            return True

        # Los administradores siempre pueden acceder
        if user.is_admin:
            return True

        # Verificar permisos específicos de usuario
        permission = UserApplicationPermission.query.filter_by(
            user_id=user.id,
            application_id=self.id
        ).first()

        if permission:
            return permission.can_access

        # Verificar si el departamento del usuario está permitido
        if self.allowed_departments and user.department:
            allowed_depts = self.get_allowed_departments_list()
            if user.department in allowed_depts:
                return True

        # Por defecto, no puede acceder a aplicaciones privadas
        return False

    def increment_access(self):
        """Incrementar contador de accesos"""
        self.access_count += 1
        self.last_accessed = datetime.utcnow()
        db.session.commit()

    def __repr__(self):
        return f'<Application {self.name}>'


class UserFavorite(db.Model):
    """Modelo de Favoritos de Usuario"""
    __tablename__ = 'user_favorites'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    order_index = db.Column(db.Integer, default=0)  # Para ordenar favoritos

    __table_args__ = (db.UniqueConstraint('user_id', 'application_id', name='unique_user_favorite'),)


class UserApplicationPermission(db.Model):
    """Modelo de Permisos de Usuario por Aplicación"""
    __tablename__ = 'user_application_permissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
    can_access = db.Column(db.Boolean, default=True, nullable=False)
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'))  # Admin que otorgó el permiso
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

    __table_args__ = (db.UniqueConstraint('user_id', 'application_id', name='unique_user_app_permission'),)


class AccessLog(db.Model):
    """Modelo de Auditoría de Accesos"""
    __tablename__ = 'access_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
    access_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45))  # IP del usuario
    user_agent = db.Column(db.Text)  # Navegador del usuario
    action = db.Column(db.String(50), default='access')  # access, favorite, unfavorite, etc.

    def __repr__(self):
        return f'<AccessLog {self.user_id}-{self.application_id}>'


# =============================================================================
# DECORADORES Y UTILIDADES
# =============================================================================

def login_required(f):
    """Decorador para requerir login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesión para acceder a esta página.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorador para requerir permisos de administrador"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Debes iniciar sesión para acceder a esta página.', 'error')
            return redirect(url_for('login'))

        user = db.session.get(User, session['user_id'])
        if not user or not user.is_admin:
            flash('No tienes permisos para acceder a esta página.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def log_access(user_id, application_id, action='access'):
    """Registrar acceso en auditoría"""
    try:
        log = AccessLog(
            user_id=user_id,
            application_id=application_id,
            action=action,
            ip_address=request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging access: {e}")


def allowed_file(filename):
    """Verificar si el archivo es una imagen válida"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# =============================================================================
# RUTAS PRINCIPALES
# =============================================================================

@app.route('/')
def index():
    """Página principal - redirige al dashboard si está logueado"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_active:
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin

            # Actualizar último login
            user.last_login = datetime.utcnow()
            db.session.commit()

            flash(f'¡Bienvenido, {user.full_name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Cerrar sesión"""
    session.clear()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal del usuario"""
    user = db.session.get(User, session['user_id'])

    # Obtener favoritos del usuario (filtrados por permisos)
    favorites_query = db.session.query(Application).join(UserFavorite).filter(
        UserFavorite.user_id == user.id
    )

    # Filtrar favoritos según permisos de aplicaciones privadas
    favorites = [app for app in favorites_query.all() if app.can_user_access(user)]

    # Obtener aplicaciones recientes (últimas 5 accedidas)
    recent_apps_query = Application.query.join(AccessLog).filter(
        AccessLog.user_id == user.id,
        AccessLog.action == 'access'
    ).order_by(AccessLog.access_time.desc()).limit(10)

    # Filtrar aplicaciones recientes según permisos
    recent_apps = [app for app in recent_apps_query.all() if app.can_user_access(user)][:5]

    # Obtener categorías con aplicaciones accesibles
    categories = Category.query.all()

    # Estadísticas rápidas (solo aplicaciones accesibles)
    all_apps = Application.query.filter_by(is_active=True).all()
    accessible_apps = [app for app in all_apps if app.can_user_access(user)]
    total_apps = len(accessible_apps)
    total_favorites = len(favorites)

    return render_template('dashboard.html',
                         user=user,
                         favorites=favorites,
                         recent_apps=recent_apps,
                         categories=categories,
                         total_apps=total_apps,
                         total_favorites=total_favorites)


@app.route('/browse')
@login_required
def browse_applications():
    """Explorar todas las aplicaciones disponibles"""
    page = request.args.get('page', 1, type=int)
    category_id = request.args.get('category', type=int)
    search = request.args.get('search', '')

    query = Application.query.filter_by(is_active=True)

    if category_id:
        query = query.filter_by(category_id=category_id)

    if search:
        search_filter = f'%{search}%'
        query = query.filter(
            db.or_(
                Application.name.like(search_filter),
                Application.description.like(search_filter),
                Application.tags.like(search_filter),
                Application.ip_address.like(search_filter)
            )
        )

    # Obtener todas las aplicaciones que coinciden con la búsqueda
    all_matching_apps = query.order_by(Application.name).all()

    # Filtrar por permisos de usuario
    user = User.query.get(session['user_id'])
    accessible_apps = [app for app in all_matching_apps if app.can_user_access(user)]

    # Paginación manual de las aplicaciones accesibles
    per_page = 12
    total = len(accessible_apps)
    start = (page - 1) * per_page
    end = start + per_page
    apps_page = accessible_apps[start:end]

    # Crear objeto de paginación manual compatible con Flask-SQLAlchemy
    class ManualPagination:
        def __init__(self, items, page, per_page, total):
            self.items = items
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = (total + per_page - 1) // per_page if total > 0 else 1
            self.has_prev = page > 1
            self.has_next = page < self.pages
            self.prev_num = page - 1 if self.has_prev else None
            self.next_num = page + 1 if self.has_next else None

        def iter_pages(self, left_edge=2, left_current=2, right_current=3, right_edge=2):
            """Generar números de página para mostrar en la paginación"""
            last = self.pages
            for num in range(1, last + 1):
                if num <= left_edge or \
                   (self.page - left_current - 1 < num < self.page + right_current) or \
                   num > last - right_edge:
                    yield num

    applications = ManualPagination(apps_page, page, per_page, total)

    categories = Category.query.order_by(Category.name).all()
    user_favorites = [fav.application_id for fav in user.favorites]

    return render_template('browse.html',
                         applications=applications,
                         categories=categories,
                         current_category=category_id,
                         search_query=search,
                         user_favorites=user_favorites)


@app.route('/access/<int:app_id>')
@login_required
def access_application(app_id):
    """Acceder a una aplicación específica"""
    application = Application.query.get_or_404(app_id)
    user_id = session['user_id']

    # Verificar permisos si es necesario
    permission = UserApplicationPermission.query.filter_by(
        user_id=user_id, application_id=app_id
    ).first()

    if permission and not permission.can_access:
        flash('No tienes permisos para acceder a esta aplicación.', 'error')
        return redirect(url_for('dashboard'))

    # Registrar acceso
    log_access(user_id, app_id, 'access')
    application.increment_access()

    # Redirigir a la aplicación
    return redirect(application.full_url)


@app.route('/favorite/<int:app_id>', methods=['POST'])
@login_required
def toggle_favorite(app_id):
    """Agregar/quitar de favoritos"""
    user_id = session['user_id']
    application = Application.query.get_or_404(app_id)

    favorite = UserFavorite.query.filter_by(
        user_id=user_id, application_id=app_id
    ).first()

    if favorite:
        # Quitar de favoritos
        db.session.delete(favorite)
        action = 'unfavorite'
        message = f'{application.name} eliminado de favoritos.'
    else:
        # Agregar a favoritos
        favorite = UserFavorite(user_id=user_id, application_id=app_id)
        db.session.add(favorite)
        action = 'favorite'
        message = f'{application.name} agregado a favoritos.'

    db.session.commit()
    log_access(user_id, app_id, action)

    if request.is_json:
        return jsonify({'success': True, 'message': message, 'is_favorite': action == 'favorite'})

    flash(message, 'success')
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/search')
@login_required
def search():
    """Búsqueda avanzada de aplicaciones"""
    query = request.args.get('q', '')
    category_id = request.args.get('category', type=int)
    tag = request.args.get('tag', '')

    if not query and not category_id and not tag:
        # Obtener todos los tags únicos de aplicaciones accesibles
        user = User.query.get(session['user_id'])
        all_apps = Application.query.filter_by(is_active=True).all()
        accessible_apps = [app for app in all_apps if app.can_user_access(user)]

        all_tags = set()
        for app in accessible_apps:
            all_tags.update(app.get_tags_list())

        return render_template('search.html',
                             applications=[],
                             categories=Category.query.all(),
                             all_tags=sorted(all_tags))

    search_query = Application.query.filter_by(is_active=True)

    if query:
        search_filter = f'%{query}%'
        search_query = search_query.filter(
            db.or_(
                Application.name.like(search_filter),
                Application.description.like(search_filter),
                Application.tags.like(search_filter),
                Application.ip_address.like(search_filter)
            )
        )

    if category_id:
        search_query = search_query.filter_by(category_id=category_id)

    if tag:
        search_query = search_query.filter(Application.tags.like(f'%{tag}%'))

    # Obtener todas las aplicaciones que coinciden con la búsqueda
    all_matching_apps = search_query.order_by(Application.access_count.desc()).all()

    # Filtrar por permisos de usuario
    user = User.query.get(session['user_id'])
    accessible_apps = [app for app in all_matching_apps if app.can_user_access(user)]

    categories = Category.query.order_by(Category.name).all()

    # Obtener todos los tags únicos de aplicaciones accesibles
    all_accessible_apps = Application.query.filter_by(is_active=True).all()
    accessible_for_tags = [app for app in all_accessible_apps if app.can_user_access(user)]
    all_tags = set()
    for app in accessible_for_tags:
        all_tags.update(app.get_tags_list())

    user_favorites = [fav.application_id for fav in user.favorites]

    return render_template('search.html',
                         applications=accessible_apps,
                         categories=categories,
                         all_tags=sorted(all_tags),
                         search_query=query,
                         selected_category=category_id,
                         selected_tag=tag,
                         user_favorites=user_favorites)


# =============================================================================
# RUTAS DE ADMINISTRACIÓN
# =============================================================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Panel de administración"""
    # Estadísticas generales
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_apps = Application.query.count()
    active_apps = Application.query.filter_by(is_active=True).count()
    total_categories = Category.query.count()

    # Actividad reciente
    recent_logs = AccessLog.query.order_by(AccessLog.access_time.desc()).limit(10).all()

    # Aplicaciones más populares
    popular_apps = Application.query.order_by(Application.access_count.desc()).limit(5).all()

    # Usuarios más activos
    from sqlalchemy import func
    active_users_stats = db.session.query(
        User.username, User.full_name, func.count(AccessLog.id).label('access_count')
    ).join(AccessLog).group_by(User.id).order_by(func.count(AccessLog.id).desc()).limit(5).all()

    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         active_users=active_users,
                         total_apps=total_apps,
                         active_apps=active_apps,
                         total_categories=total_categories,
                         recent_logs=recent_logs,
                         popular_apps=popular_apps,
                         active_users_stats=active_users_stats)


@app.route('/admin/users')
@admin_required
def admin_users():
    """Gestión de usuarios"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = User.query
    if search:
        search_filter = f'%{search}%'
        query = query.filter(
            db.or_(
                User.username.like(search_filter),
                User.full_name.like(search_filter),
                User.email.like(search_filter),
                User.department.like(search_filter)
            )
        )

    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )

    return render_template('admin/users.html', users=users, search_query=search)


@app.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    """Crear nuevo usuario"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        full_name = request.form['full_name']
        department = request.form.get('department', '')
        password = request.form['password']
        is_admin = 'is_admin' in request.form

        # Verificar si el usuario ya existe
        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya existe.', 'error')
            return render_template('admin/create_user.html')

        if User.query.filter_by(email=email).first():
            flash('El email ya está registrado.', 'error')
            return render_template('admin/create_user.html')

        # Crear nuevo usuario
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            department=department,
            is_admin=is_admin
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash(f'Usuario {username} creado exitosamente.', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin/create_user.html')


@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    """Activar/desactivar usuario"""
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()

    status = 'activado' if user.is_active else 'desactivado'
    flash(f'Usuario {user.username} {status} exitosamente.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    """Editar usuario"""
    user = User.query.get_or_404(user_id)

    # Evitar que un admin se desactive a sí mismo
    current_user = User.query.get(session['user_id'])

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.full_name = request.form['full_name']
        user.department = request.form.get('department', '')

        # Solo permitir cambios de admin si no es el usuario actual o si hay otros admins
        if user_id != current_user.id or User.query.filter_by(is_admin=True).count() > 1:
            user.is_admin = 'is_admin' in request.form

        user.is_active = 'is_active' in request.form

        # Cambiar contraseña solo si se proporciona
        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)

        # Verificar que username y email sean únicos
        existing_user = User.query.filter(
            User.id != user_id,
            db.or_(User.username == user.username, User.email == user.email)
        ).first()

        if existing_user:
            flash('El nombre de usuario o email ya están en uso.', 'error')
            return render_template('admin/edit_user.html', user=user)

        try:
            db.session.commit()
            flash(f'Usuario {user.username} actualizado exitosamente.', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash('Error al actualizar el usuario.', 'error')

    return render_template('admin/edit_user.html', user=user)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Eliminar usuario"""
    user = User.query.get_or_404(user_id)
    current_user = User.query.get(session['user_id'])

    # No permitir que un admin se elimine a sí mismo
    if user_id == current_user.id:
        flash('No puedes eliminar tu propia cuenta.', 'error')
        return redirect(url_for('admin_users'))

    # Verificar que no sea el último admin
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash('No se puede eliminar el último administrador del sistema.', 'error')
        return redirect(url_for('admin_users'))

    try:
        # Los favoritos y logs se eliminan automáticamente por cascade
        db.session.delete(user)
        db.session.commit()
        flash(f'Usuario {user.username} eliminado exitosamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar el usuario. Puede que tenga datos relacionados.', 'error')

    return redirect(url_for('admin_users'))


@app.route('/admin/applications')
@admin_required
def admin_applications():
    """Gestión de aplicaciones"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    category_id = request.args.get('category', type=int)

    query = Application.query
    if search:
        search_filter = f'%{search}%'
        query = query.filter(
            db.or_(
                Application.name.like(search_filter),
                Application.description.like(search_filter),
                Application.ip_address.like(search_filter),
                Application.tags.like(search_filter)
            )
        )

    if category_id:
        query = query.filter_by(category_id=category_id)

    applications = query.order_by(Application.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )

    categories = Category.query.order_by(Category.name).all()

    return render_template('admin/applications.html',
                         applications=applications,
                         categories=categories,
                         search_query=search,
                         selected_category=category_id)


@app.route('/admin/applications/create', methods=['GET', 'POST'])
@admin_required
def admin_create_application():
    """Crear nueva aplicación"""
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        ip_address = request.form['ip_address']
        port = request.form.get('port', type=int)
        protocol = request.form.get('protocol', 'http')
        url_path = request.form.get('url_path', '/')
        category_id = request.form.get('category_id', type=int)
        tags = request.form.get('tags', '')
        requires_auth = 'requires_auth' in request.form
        auth_username = request.form.get('auth_username', '')

        # Campos de privacidad
        is_private = 'is_private' in request.form
        allowed_departments = request.form.get('allowed_departments', '')

        # Validar IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            flash('Dirección IP inválida.', 'error')
            return render_template('admin/create_application.html',
                                 categories=Category.query.all())

        # Manejar archivo de icono
        icon_filename = None
        if 'icon' in request.files:
            file = request.files['icon']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Agregar timestamp para evitar conflictos
                name_part = filename.rsplit('.', 1)[0]
                ext_part = filename.rsplit('.', 1)[1]
                icon_filename = f"{name_part}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{ext_part}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], icon_filename))

        # Limpiar y procesar departamentos permitidos
        if allowed_departments and is_private:
            departments = [dept.strip() for dept in allowed_departments.split(',') if dept.strip()]
            allowed_departments = ','.join(departments)
        else:
            allowed_departments = ''

        # Crear aplicación
        application = Application(
            name=name,
            description=description,
            ip_address=ip_address,
            port=port,
            protocol=protocol,
            url_path=url_path,
            icon_filename=icon_filename,
            category_id=category_id,
            tags=tags,
            requires_auth=requires_auth,
            auth_username=auth_username if requires_auth else None,
            is_private=is_private,
            allowed_departments=allowed_departments
        )

        db.session.add(application)
        db.session.commit()

        privacy_msg = " (privada)" if is_private else " (pública)"
        flash(f'Aplicación {name}{privacy_msg} creada exitosamente.', 'success')
        return redirect(url_for('admin_applications'))

    categories = Category.query.order_by(Category.name).all()

    # Obtener departamentos únicos para el formulario
    departments = db.session.query(User.department).filter(
        User.department.isnot(None),
        User.department != ''
    ).distinct().all()
    departments = [dept[0] for dept in departments if dept[0]]

    return render_template('admin/create_application.html',
                          categories=categories,
                          departments=departments)


@app.route('/admin/applications/<int:app_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_application(app_id):
    """Editar aplicación"""
    application = Application.query.get_or_404(app_id)

    if request.method == 'POST':
        application.name = request.form['name']
        application.description = request.form.get('description', '')
        application.ip_address = request.form['ip_address']
        application.port = request.form.get('port', type=int)
        application.protocol = request.form.get('protocol', 'http')
        application.url_path = request.form.get('url_path', '/')
        application.category_id = request.form.get('category_id', type=int)
        application.tags = request.form.get('tags', '')
        application.requires_auth = 'requires_auth' in request.form
        application.auth_username = request.form.get('auth_username', '') if application.requires_auth else None

        # Campos de privacidad
        application.is_private = 'is_private' in request.form
        allowed_departments = request.form.get('allowed_departments', '')

        # Limpiar y procesar departamentos permitidos
        if allowed_departments and application.is_private:
            departments = [dept.strip() for dept in allowed_departments.split(',') if dept.strip()]
            application.allowed_departments = ','.join(departments)
        else:
            application.allowed_departments = ''

        application.updated_at = datetime.utcnow()

        # Validar IP
        try:
            ipaddress.ip_address(application.ip_address)
        except ValueError:
            flash('Dirección IP inválida.', 'error')
            return render_template('admin/edit_application.html',
                                 application=application,
                                 categories=Category.query.all())

        # Manejar nuevo icono
        if 'icon' in request.files:
            file = request.files['icon']
            if file and file.filename and allowed_file(file.filename):
                # Eliminar icono anterior si existe
                if application.icon_filename:
                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], application.icon_filename)
                    if os.path.exists(old_path):
                        os.remove(old_path)

                filename = secure_filename(file.filename)
                name_part = filename.rsplit('.', 1)[0]
                ext_part = filename.rsplit('.', 1)[1]
                icon_filename = f"{name_part}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{ext_part}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], icon_filename))
                application.icon_filename = icon_filename

        db.session.commit()

        privacy_msg = " como privada" if application.is_private else " como pública"
        flash(f'Aplicación {application.name} actualizada{privacy_msg} exitosamente.', 'success')
        return redirect(url_for('admin_applications'))

    categories = Category.query.order_by(Category.name).all()

    # Obtener departamentos únicos para el formulario
    departments = db.session.query(User.department).filter(
        User.department.isnot(None),
        User.department != ''
    ).distinct().all()
    departments = [dept[0] for dept in departments if dept[0]]

    return render_template('admin/edit_application.html',
                         application=application,
                         categories=categories,
                         departments=departments)


@app.route('/admin/applications/<int:app_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_application(app_id):
    """Activar/desactivar aplicación"""
    application = Application.query.get_or_404(app_id)
    application.is_active = not application.is_active
    db.session.commit()

    status = 'activada' if application.is_active else 'desactivada'
    flash(f'Aplicación {application.name} {status} exitosamente.', 'success')
    return redirect(url_for('admin_applications'))


@app.route('/admin/applications/<int:app_id>/delete', methods=['POST'])
@admin_required
def admin_delete_application(app_id):
    """Eliminar aplicación"""
    application = Application.query.get_or_404(app_id)

    try:
        # Eliminar archivo de icono si existe
        if application.icon_filename:
            icon_path = os.path.join(app.config['UPLOAD_FOLDER'], application.icon_filename)
            if os.path.exists(icon_path):
                os.remove(icon_path)

        # Los favoritos y logs se eliminan automáticamente por cascade
        db.session.delete(application)
        db.session.commit()
        flash(f'Aplicación {application.name} eliminada exitosamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar la aplicación. Puede que tenga datos relacionados.', 'error')

    return redirect(url_for('admin_applications'))


@app.route('/admin/logs')
@admin_required
def admin_logs():
    """Ver logs de auditoría"""
    page = request.args.get('page', 1, type=int)
    user_id = request.args.get('user', type=int)
    app_id = request.args.get('app', type=int)
    action = request.args.get('action', '')

    query = AccessLog.query
    if user_id:
        query = query.filter_by(user_id=user_id)
    if app_id:
        query = query.filter_by(application_id=app_id)
    if action:
        query = query.filter_by(action=action)

    logs = query.order_by(AccessLog.access_time.desc()).paginate(
        page=page, per_page=50, error_out=False
    )

    users = User.query.order_by(User.full_name).all()
    applications = Application.query.order_by(Application.name).all()
    actions = ['access', 'favorite', 'unfavorite']

    return render_template('admin/logs.html',
                         logs=logs,
                         users=users,
                         applications=applications,
                         actions=actions,
                         selected_user=user_id,
                         selected_app=app_id,
                         selected_action=action)


@app.route('/admin/categories', methods=['GET', 'POST'])
@admin_required
def admin_categories():
    """Gestión de categorías"""
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        color = request.form.get('color', '#007bff')
        icon = request.form.get('icon', 'fa-folder')

        if Category.query.filter_by(name=name).first():
            flash('Ya existe una categoría con ese nombre.', 'error')
        else:
            category = Category(
                name=name,
                description=description,
                color=color,
                icon=icon
            )
            db.session.add(category)
            db.session.commit()
            flash(f'Categoría {name} creada exitosamente.', 'success')

    categories = Category.query.order_by(Category.name).all()
    return render_template('admin/categories.html', categories=categories)


@app.route('/admin/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_category(category_id):
    """Editar categoría"""
    category = Category.query.get_or_404(category_id)

    if request.method == 'POST':
        category.name = request.form['name']
        category.description = request.form.get('description', '')
        category.color = request.form.get('color', '#007bff')
        category.icon = request.form.get('icon', 'fa-folder')

        # Verificar que el nombre sea único
        existing_category = Category.query.filter(
            Category.id != category_id,
            Category.name == category.name
        ).first()

        if existing_category:
            flash('Ya existe una categoría con ese nombre.', 'error')
            return render_template('admin/edit_category.html', category=category)

        try:
            db.session.commit()
            flash(f'Categoría {category.name} actualizada exitosamente.', 'success')
            return redirect(url_for('admin_categories'))
        except Exception as e:
            db.session.rollback()
            flash('Error al actualizar la categoría.', 'error')

    return render_template('admin/edit_category.html', category=category)


@app.route('/admin/categories/<int:category_id>/delete', methods=['POST'])
@admin_required
def admin_delete_category(category_id):
    """Eliminar categoría"""
    category = Category.query.get_or_404(category_id)

    # Verificar si la categoría tiene aplicaciones asociadas
    app_count = Application.query.filter_by(category_id=category_id).count()
    if app_count > 0:
        flash(f'No se puede eliminar la categoría {category.name} porque tiene {app_count} aplicaciones asociadas.', 'error')
        return redirect(url_for('admin_categories'))

    try:
        db.session.delete(category)
        db.session.commit()
        flash(f'Categoría {category.name} eliminada exitosamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar la categoría.', 'error')

    return redirect(url_for('admin_categories'))


@app.route('/admin/statistics')
@admin_required
def admin_statistics():
    """Estadísticas detalladas"""
    from sqlalchemy import func, desc

    # Estadísticas de usuarios
    users_by_department = db.session.query(
        User.department, func.count(User.id).label('count')
    ).group_by(User.department).all()

    # Aplicaciones más accedidas
    most_accessed = db.session.query(
        Application.name, Application.access_count
    ).order_by(desc(Application.access_count)).limit(10).all()

    # Actividad por día (últimos 30 días)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    daily_activity = db.session.query(
        func.date(AccessLog.access_time).label('date'),
        func.count(AccessLog.id).label('count')
    ).filter(AccessLog.access_time >= thirty_days_ago).group_by(
        func.date(AccessLog.access_time)
    ).order_by('date').all()

    # Usuarios más activos
    top_users = db.session.query(
        User.full_name, User.username, func.count(AccessLog.id).label('access_count')
    ).join(AccessLog).group_by(User.id).order_by(
        desc(func.count(AccessLog.id))
    ).limit(10).all()

    return render_template('admin/statistics.html',
                         users_by_department=users_by_department,
                         most_accessed=most_accessed,
                         daily_activity=daily_activity,
                         top_users=top_users)


# =============================================================================
# RUTAS DE GESTIÓN DE APLICACIONES PRIVADAS
# =============================================================================

@app.route('/admin/applications/<int:app_id>/permissions')
@admin_required
def admin_application_permissions(app_id):
    """Gestionar permisos de aplicación privada"""
    application = Application.query.get_or_404(app_id)

    # Obtener permisos específicos de usuarios
    permissions = db.session.query(
        UserApplicationPermission, User
    ).join(User, UserApplicationPermission.user_id == User.id).filter(
        UserApplicationPermission.application_id == app_id
    ).all()

    # Obtener todos los usuarios para agregar permisos
    all_users = User.query.filter_by(is_active=True).order_by(User.full_name).all()

    # Obtener departamentos únicos
    departments = db.session.query(User.department).filter(
        User.department.isnot(None),
        User.department != ''
    ).distinct().all()
    departments = [dept[0] for dept in departments if dept[0]]

    return render_template('admin/application_permissions.html',
                         application=application,
                         permissions=permissions,
                         all_users=all_users,
                         departments=departments)


@app.route('/admin/applications/<int:app_id>/permissions/user', methods=['POST'])
@admin_required
def admin_add_user_permission(app_id):
    """Agregar permiso específico a un usuario"""
    application = Application.query.get_or_404(app_id)
    user_id = request.form.get('user_id', type=int)
    can_access = 'can_access' in request.form
    notes = request.form.get('notes', '')

    if not user_id:
        flash('Debe seleccionar un usuario.', 'error')
        return redirect(url_for('admin_application_permissions', app_id=app_id))

    # Verificar si ya existe el permiso
    existing_permission = UserApplicationPermission.query.filter_by(
        user_id=user_id,
        application_id=app_id
    ).first()

    if existing_permission:
        # Actualizar permiso existente
        existing_permission.can_access = can_access
        existing_permission.notes = notes
        existing_permission.granted_by = session['user_id']
        existing_permission.granted_at = datetime.utcnow()
        flash('Permiso actualizado exitosamente.', 'success')
    else:
        # Crear nuevo permiso
        permission = UserApplicationPermission(
            user_id=user_id,
            application_id=app_id,
            can_access=can_access,
            granted_by=session['user_id'],
            notes=notes
        )
        db.session.add(permission)
        flash('Permiso agregado exitosamente.', 'success')

    db.session.commit()
    return redirect(url_for('admin_application_permissions', app_id=app_id))


@app.route('/admin/applications/<int:app_id>/permissions/<int:permission_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user_permission(app_id, permission_id):
    """Eliminar permiso específico de usuario"""
    permission = UserApplicationPermission.query.get_or_404(permission_id)

    if permission.application_id != app_id:
        flash('Error: ID de aplicación no coincide.', 'error')
        return redirect(url_for('admin_application_permissions', app_id=app_id))

    db.session.delete(permission)
    db.session.commit()

    flash('Permiso eliminado exitosamente.', 'success')
    return redirect(url_for('admin_application_permissions', app_id=app_id))


@app.route('/admin/applications/<int:app_id>/privacy', methods=['POST'])
@admin_required
def admin_update_application_privacy(app_id):
    """Actualizar configuración de privacidad de aplicación"""
    application = Application.query.get_or_404(app_id)

    application.is_private = 'is_private' in request.form
    allowed_departments = request.form.get('allowed_departments', '')

    # Limpiar y validar departamentos
    if allowed_departments:
        departments = [dept.strip() for dept in allowed_departments.split(',') if dept.strip()]
        application.allowed_departments = ','.join(departments)
    else:
        application.allowed_departments = ''

    application.updated_at = datetime.utcnow()

    try:
        db.session.commit()

        privacy_status = "privada" if application.is_private else "pública"
        flash(f'Aplicación {application.name} configurada como {privacy_status}.', 'success')

        # Si se hizo privada, mostrar información adicional
        if application.is_private:
            if application.allowed_departments:
                dept_list = application.get_allowed_departments_list()
                flash(f'Departamentos permitidos: {", ".join(dept_list)}', 'info')

            permissions_count = application.permissions.count()
            if permissions_count > 0:
                flash(f'Permisos específicos de usuario: {permissions_count}', 'info')

    except Exception as e:
        db.session.rollback()
        flash('Error al actualizar la configuración de privacidad.', 'error')

    return redirect(url_for('admin_application_permissions', app_id=app_id))


@app.route('/admin/permissions')
@admin_required
def admin_all_permissions():
    """Vista general de todos los permisos de aplicaciones privadas"""
    page = request.args.get('page', 1, type=int)
    user_id = request.args.get('user', type=int)
    app_id = request.args.get('app', type=int)

    # Consulta base de aplicaciones privadas
    private_apps_query = Application.query.filter_by(is_private=True, is_active=True)

    if app_id:
        private_apps_query = private_apps_query.filter_by(id=app_id)

    private_apps = private_apps_query.all()

    # Obtener permisos específicos
    permissions_query = db.session.query(
        UserApplicationPermission, User, Application
    ).join(
        User, UserApplicationPermission.user_id == User.id
    ).join(
        Application, UserApplicationPermission.application_id == Application.id
    ).filter(Application.is_private == True)

    if user_id:
        permissions_query = permissions_query.filter(User.id == user_id)
    if app_id:
        permissions_query = permissions_query.filter(Application.id == app_id)

    permissions = permissions_query.order_by(
        Application.name, User.full_name
    ).paginate(page=page, per_page=20, error_out=False)

    # Datos para filtros - INCLUIR TODAS LAS APLICACIONES ACTIVAS, no solo las privadas
    users = User.query.filter_by(is_active=True).order_by(User.full_name).all()
    applications = Application.query.filter_by(is_active=True).order_by(Application.name).all()

    # Obtener departamentos únicos de usuarios
    departments = list(set([user.department for user in users if user.department]))
    departments.sort()

    return render_template('admin/all_permissions.html',
                         private_apps=private_apps,
                         permissions=permissions,
                         users=users,
                         applications=applications,
                         departments=departments,
                         selected_user=user_id,
                         selected_app=app_id)


@app.route('/admin/permissions/bulk', methods=['POST'])
@admin_required
def admin_bulk_permissions():
    """Gestión masiva de permisos"""
    action = request.form.get('action')
    app_id = request.form.get('app_id', type=int)
    department = request.form.get('department')
    user_ids = request.form.getlist('user_ids', type=int)

    if not app_id:
        flash('Debe seleccionar una aplicación.', 'error')
        return redirect(url_for('admin_all_permissions'))

    application = Application.query.get_or_404(app_id)

    if action == 'grant_department':
        # Otorgar acceso a todo un departamento
        if not department:
            flash('Debe especificar un departamento.', 'error')
            return redirect(url_for('admin_all_permissions'))

        users_in_dept = User.query.filter_by(department=department, is_active=True).all()
        count = 0

        for user in users_in_dept:
            # Verificar si ya existe el permiso
            existing = UserApplicationPermission.query.filter_by(
                user_id=user.id,
                application_id=app_id
            ).first()

            if not existing:
                permission = UserApplicationPermission(
                    user_id=user.id,
                    application_id=app_id,
                    can_access=True,
                    granted_by=session['user_id'],
                    notes=f'Acceso otorgado por departamento: {department}'
                )
                db.session.add(permission)
                count += 1

        db.session.commit()
        flash(f'Acceso otorgado a {count} usuarios del departamento {department}.', 'success')

    elif action == 'grant_users':
        # Otorgar acceso a usuarios específicos
        if not user_ids:
            flash('Debe seleccionar al menos un usuario.', 'error')
            return redirect(url_for('admin_all_permissions'))

        count = 0
        for user_id in user_ids:
            existing = UserApplicationPermission.query.filter_by(
                user_id=user_id,
                application_id=app_id
            ).first()

            if not existing:
                permission = UserApplicationPermission(
                    user_id=user_id,
                    application_id=app_id,
                    can_access=True,
                    granted_by=session['user_id'],
                    notes='Acceso otorgado por selección masiva'
                )
                db.session.add(permission)
                count += 1

        db.session.commit()
        flash(f'Acceso otorgado a {count} usuarios.', 'success')

    elif action == 'revoke_users':
        # Revocar acceso a usuarios específicos
        if not user_ids:
            flash('Debe seleccionar al menos un usuario.', 'error')
            return redirect(url_for('admin_all_permissions'))

        count = UserApplicationPermission.query.filter(
            UserApplicationPermission.user_id.in_(user_ids),
            UserApplicationPermission.application_id == app_id
        ).delete(synchronize_session=False)

        db.session.commit()
        flash(f'Acceso revocado a {count} usuarios.', 'success')

    return redirect(url_for('admin_all_permissions'))


# =============================================================================
# PÁGINAS DE ERROR
# =============================================================================

@app.errorhandler(403)
def forbidden(error):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500


# =============================================================================
# FUNCIONES DE INICIALIZACIÓN
# =============================================================================

def create_default_data():
    """Crear datos por defecto"""
    # Crear usuario administrador por defecto
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@empresa.com',
            full_name='Administrador del Sistema',
            department='IT',
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)

    # Crear categorías por defecto
    default_categories = [
        {'name': 'Servidores', 'description': 'Servidores de la empresa', 'color': '#dc3545', 'icon': 'fa-server'},
        {'name': 'Aplicaciones Web', 'description': 'Aplicaciones web internas', 'color': '#28a745', 'icon': 'fa-globe'},
        {'name': 'Bases de Datos', 'description': 'Sistemas de base de datos', 'color': '#007bff', 'icon': 'fa-database'},
        {'name': 'Monitoreo', 'description': 'Herramientas de monitoreo', 'color': '#ffc107', 'icon': 'fa-chart-line'},
        {'name': 'Red', 'description': 'Equipos de red', 'color': '#6c757d', 'icon': 'fa-network-wired'}
    ]

    for cat_data in default_categories:
        if not Category.query.filter_by(name=cat_data['name']).first():
            category = Category(**cat_data)
            db.session.add(category)

    db.session.commit()


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_data()

    app.run(debug=True, host='0.0.0.0', port=5000)

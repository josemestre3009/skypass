# PROMPT DE GENERACIÓN — SKYPASS v3.0 MULTI-TENANT

> **Propósito:** Prompt completo y autocontenido para generar SkyPass como plataforma multi-tenant SaaS. Cada empresa (ISP) tiene su propia landing page, login, panel admin y credenciales de API almacenadas en base de datos. Un único SuperAdmin gestiona todos los tenants y la cuenta compartida de WhatsApp.

---

## CONCEPTO MULTI-TENANT

```
skypass.com/
│
├── /                        → Landing general de SkyPass
│                              Botón "Iniciar Sesión" → /admin/login
│
├── /admin/login             → Login ÚNICO para admins de ISP y SuperAdmin
│     ├── Si es SuperAdmin   → redirige a /superadmin/dashboard
│     └── Si es Admin ISP    → carga su tenant por tenant_id, redirige a /admin/dashboard
│
├── /admin/dashboard         → Panel admin (datos de SU empresa, sin slug en URL)
├── /admin/historial         → Historial filtrado por su tenant
├── /admin/configuracion     → Config de su empresa (WispHub, GenieACS, branding)
│
├── /superadmin/dashboard    → Panel SuperAdmin global
├── /superadmin/tenants      → Crear y gestionar ISPs
│
├── /{empresa}/              → Landing del cliente con branding del ISP
├── /{empresa}/login         → Login del cliente con cédula + OTP WhatsApp
└── /{empresa}/dashboard     → Portal WiFi del cliente
```

Cada tenant (ISP) tiene:
- Su propia **landing page** con logo, colores y nombre de empresa en `/{slug}`
- Sus **credenciales de API** guardadas en BD: WispHub URL+Key, GenieACS URL
- Sus **datos aislados**: historial, límites, dispositivos
- Su propio **admin** que accede por el login general `/admin/login`

El **SuperAdmin** comparte el mismo login `/admin/login` y el sistema lo redirige al panel global.

---

## STACK TECNOLÓGICO

| Capa | Tecnología |
|---|---|
| Backend | Python 3.11+ / Flask 3.x |
| Base de datos | PostgreSQL 15+ |
| ORM / Migraciones | SQLAlchemy 2.x + Alembic |
| Frontend | HTML5 + Jinja2 + CSS vanilla + JS vanilla |
| Servidor WSGI | Gunicorn (4 workers) |
| Proxy reverso | Nginx / EasyPanel (SSL estándar, un solo dominio) |
| WhatsApp | YCloud API — compartido, configurado por SuperAdmin |
| Gestión CPE | GenieACS TR-069 — URL **por tenant**, en BD |
| Gestión ISP | WispHub API — URL + Key **por tenant**, en BD |
| OTPs / Bloqueos | PostgreSQL (tablas `otps` e `ip_blocks`) |
| Rate limiting | Flask-Limiter con backend en memoria (1 worker) |
| Hashing | werkzeug.security (pbkdf2:sha256) |

---

## ARQUITECTURA COMPLETA

```
Internet
    │
    ▼
┌──────────────────────────────────────────────────────────────┐
│  NGINX / EasyPanel  (SSL estándar — solo skypass.com)        │
│  Un solo dominio, sin wildcard, sin configuración especial   │
└──────────────────────────┬───────────────────────────────────┘
                           │ proxy_pass → :8000
┌──────────────────────────▼───────────────────────────────────┐
│                    GUNICORN / FLASK APP                       │
│                                                              │
│  before_request → TenantMiddleware                           │
│    /{slug}/...  → lee slug de URL → busca Tenant en BD       │
│    /admin/...   → tenant viene de session['admin_tenant_id'] │
│    /superadmin/ → sin tenant (ruta global)                   │
│                                                              │
│  ┌───────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │  BP Clientes  │  │   BP Admin       │  │ BP SuperAdmin │ │
│  │  /<slug>/...  │  │  /admin/...      │  │ /superadmin/  │ │
│  └──────┬────────┘  └────────┬─────────┘  └──────┬────────┘ │
│         │                   │                    │          │
│  ┌──────▼───────────────────▼────────────────────▼────────┐ │
│  │              Capa de Servicios (tenant-aware)           │ │
│  │  WispHubService(tenant)  GenieACService(tenant)         │ │
│  │  YCloudService(global)   OTPService(db)                 │ │
│  └──────────────────────────┬──────────────────────────────┘ │
│                             │                               │
│                     ┌───────▼──────────────────┐           │
│                     │        PostgreSQL         │           │
│                     │  tenants, otps, ip_blocks │           │
│                     │  change_history, limits   │           │
│                     └──────────────────────────┘           │
└──────────────────────────────────────────────────────────────┘
         │  WispHub API          │  GenieACS API        │ YCloud
         │  (URL por tenant)     │  (URL por tenant)    │ (global)
```

---

## ESTRUCTURA DE ARCHIVOS

```
skypass/
├── app.py                        # create_app(), registra blueprints y middleware
├── config.py                     # Config, DevelopmentConfig, ProductionConfig
├── extensions.py                 # db, limiter (singletons)
├── middleware/
│   └── tenant.py                 # TenantMiddleware — resuelve g.tenant por request
├── models/
│   ├── __init__.py
│   ├── tenant.py                 # Tenant (empresa ISP)
│   ├── tenant_config.py          # TenantConfig (clave-valor por tenant)
│   ├── global_setting.py         # GlobalSetting (YCloud y config global)
│   ├── super_admin.py            # SuperAdmin (usuario superadmin)
│   ├── admin_user.py             # AdminUser (admin por tenant)
│   ├── change_history.py         # ChangeHistory (con tenant_id)
│   ├── change_limit.py           # ChangeLimit (con tenant_id)
│   └── user_limit.py             # UserLimit (con tenant_id)
├── blueprints/
│   ├── customers/
│   │   ├── __init__.py
│   │   ├── routes.py             # Login cliente, OTP, dashboard, cambios WiFi
│   │   └── decorators.py        # @cliente_requerido (verifica sesión + tenant)
│   ├── admin/
│   │   ├── __init__.py
│   │   ├── routes.py             # Panel admin por tenant
│   │   └── decorators.py        # @admin_requerido (verifica admin + tenant)
│   └── superadmin/
│       ├── __init__.py
│       ├── routes.py             # Panel SuperAdmin global
│       └── decorators.py        # @superadmin_requerido
├── services/
│   ├── wisphub.py                # WispHubService(base_url, api_key)
│   ├── genieacs.py               # GenieACService(base_url)
│   ├── ycloud.py                 # YCloudService(api_key, sender_id, from_number)
│   └── otp.py                    # OTPService(db, tenant_id)
├── helpers/
│   └── tenant_services.py        # get_wisphub(tenant), get_genieacs(tenant), get_ycloud()
├── migrations/                   # Alembic
├── templates/
│   ├── base_tenant.html          # Base con variables de branding del tenant
│   ├── base_superadmin.html      # Base para panel superadmin
│   ├── landing/
│   │   └── index.html            # Landing page pública del tenant
│   ├── users/
│   │   ├── user_login.html
│   │   ├── user_otp.html
│   │   ├── user_seleccionar_servicio.html
│   │   ├── user_dashboard.html
│   │   ├── user_cambiar_clave.html
│   │   └── user_cambiar_nombre_red.html
│   ├── admin/
│   │   ├── admin_login.html
│   │   ├── admin_dashboard.html
│   │   ├── admin_historial.html
│   │   ├── admin_limites.html
│   │   ├── admin_configuracion.html
│   │   ├── admin_cambiar_wifi_cliente.html
│   │   ├── buscar_cliente.html
│   │   ├── dispositivos_conectados.html
│   │   └── soporte_ips.html
│   ├── superadmin/
│   │   ├── sa_login.html
│   │   ├── sa_dashboard.html
│   │   ├── sa_tenants.html
│   │   ├── sa_tenant_form.html   # Crear / editar tenant
│   │   ├── sa_configuracion.html # Config global (YCloud)
│   │   └── sa_estadisticas.html
│   └── errors/
│       ├── 404.html
│       └── tenant_inactivo.html
├── static/
│   ├── global/
│   │   ├── styles_admin.css
│   │   ├── styles_superadmin.css
│   │   └── session-timeout.js
│   └── tenants/                  # Logos subidos por tenant (o usar URL externa)
│       └── {slug}/
│           └── logo.png
├── .env.example
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── alembic.ini
```

---

## ESQUEMA COMPLETO DE BASE DE DATOS — POSTGRESQL

### Tabla: `tenants`

```sql
CREATE TABLE tenants (
    id           SERIAL       PRIMARY KEY,
    slug         VARCHAR(50)  NOT NULL UNIQUE,  -- segmento de URL: "misp1"
    nombre       VARCHAR(150) NOT NULL,          -- "Mi ISP S.A."
    is_active    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_tenants_slug ON tenants(slug);
```

### Tabla: `tenant_configs`

Almacena toda la configuración específica del tenant (equivale a las variables .env del v1, pero en BD).

```sql
CREATE TABLE tenant_configs (
    id          SERIAL       PRIMARY KEY,
    tenant_id   INTEGER      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    clave       VARCHAR(100) NOT NULL,
    valor       TEXT,                           -- NULL = no configurado
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, clave)
);

CREATE INDEX idx_tenant_configs_tenant ON tenant_configs(tenant_id);
```

**Claves válidas en `tenant_configs`:**

| clave | descripción | ejemplo |
|---|---|---|
| `wisphub_url` | URL base de la API WispHub del tenant | `https://api.wisphub.io/api/clientes` |
| `wisphub_api_key` | API Key de WispHub del tenant | `Token abc123...` |
| `genieacs_url` | URL de GenieACS del tenant | `http://192.168.1.10:7557` |
| `max_cambios_mes` | Límite mensual de cambios (default global) | `2` |
| `empresa_nombre` | Nombre a mostrar en UI y WhatsApp | `Sky Soluciones` |
| `empresa_logo_url` | URL o path del logo | `/static/tenants/misp1/logo.png` |
| `empresa_color_primario` | Color principal HEX | `#1a73e8` |
| `empresa_color_secundario` | Color secundario HEX | `#ffffff` |
| `empresa_color_texto` | Color de texto HEX | `#212121` |
| `whatsapp_template_otp` | Nombre del template WA para OTP | `auth_skypass` |
| `whatsapp_template_confirmacion` | Nombre del template WA para confirmación | `solicitud_cambio_skypass_v2` |

### Tabla: `global_settings`

Configuración global del sistema (solo SuperAdmin puede editarla).

```sql
CREATE TABLE global_settings (
    clave       VARCHAR(100) PRIMARY KEY,
    valor       TEXT,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Seeds iniciales
INSERT INTO global_settings (clave, valor) VALUES
  ('ycloud_api_key',      NULL),
  ('ycloud_sender_id',    NULL),
  ('ycloud_from_number',  NULL),
  ('app_nombre',          'SkyPass'),
  ('app_version',         '3.0');
```

### Tabla: `super_admins`

```sql
CREATE TABLE super_admins (
    id          SERIAL       PRIMARY KEY,
    username    VARCHAR(80)  NOT NULL UNIQUE,
    email       VARCHAR(120) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

### Tabla: `admin_users`

Admins por tenant.

```sql
CREATE TABLE admin_users (
    id          SERIAL       PRIMARY KEY,
    tenant_id   INTEGER      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username    VARCHAR(80)  NOT NULL,
    email       VARCHAR(120) NOT NULL,
    password    VARCHAR(255) NOT NULL,
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, username),
    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_admin_users_tenant ON admin_users(tenant_id);
```

### Tabla: `change_history`

```sql
CREATE TABLE change_history (
    id           SERIAL       PRIMARY KEY,
    tenant_id    INTEGER      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    admin_id     INTEGER      REFERENCES admin_users(id) ON DELETE SET NULL,
    cedula       VARCHAR(20)  NOT NULL,
    tipo_cambio  VARCHAR(20)  NOT NULL CHECK (tipo_cambio IN ('Password', 'SSID')),
    valor_nuevo  TEXT         NOT NULL,
    ip_onu       INET,
    fecha        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_change_history_tenant  ON change_history(tenant_id);
CREATE INDEX idx_change_history_cedula  ON change_history(tenant_id, cedula);
CREATE INDEX idx_change_history_fecha   ON change_history(fecha DESC);
```

### Tabla: `change_limits`

```sql
CREATE TABLE change_limits (
    id                 SERIAL       PRIMARY KEY,
    tenant_id          INTEGER      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cedula             VARCHAR(20)  NOT NULL,
    mes_anio           CHAR(7)      NOT NULL,   -- 'YYYY-MM'
    cambios_realizados INTEGER      NOT NULL DEFAULT 0,
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, cedula, mes_anio)
);
```

### Tabla: `otps`

```sql
CREATE TABLE otps (
    id          SERIAL       PRIMARY KEY,
    tenant_id   INTEGER      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cedula      VARCHAR(20)  NOT NULL,
    codigo      VARCHAR(6)   NOT NULL,
    intentos    INTEGER      NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, cedula)
);

CREATE INDEX idx_otps_tenant_cedula ON otps(tenant_id, cedula);
```

### Tabla: `ip_blocks`

```sql
CREATE TABLE ip_blocks (
    id              SERIAL       PRIMARY KEY,
    tenant_id       INTEGER      REFERENCES tenants(id) ON DELETE CASCADE,
    ip              VARCHAR(45)  NOT NULL,
    accion          VARCHAR(50)  NOT NULL,   -- 'login' | 'otp'
    bloqueado_hasta TIMESTAMPTZ  NOT NULL,
    UNIQUE (tenant_id, ip, accion)
);

CREATE INDEX idx_ip_blocks_lookup ON ip_blocks(tenant_id, ip, accion);
```

**Limpieza automática de registros expirados** — agregar en una tarea periódica o en `before_request`:

```sql
DELETE FROM otps      WHERE expires_at      < NOW();
DELETE FROM ip_blocks WHERE bloqueado_hasta < NOW();
```

### Tabla: `user_limits`

```sql
CREATE TABLE user_limits (
    id                   SERIAL       PRIMARY KEY,
    tenant_id            INTEGER      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ip                   INET         NOT NULL,
    cedula               VARCHAR(20)  NOT NULL,
    nombre               VARCHAR(255),
    limite_personalizado INTEGER,               -- NULL = usar max_cambios_mes del tenant
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, ip)
);
```

---

## MODELOS SQLALCHEMY

### models/tenant.py

```python
from extensions import db
from datetime import datetime, timezone

class Tenant(db.Model):
    __tablename__ = "tenants"
    id         = db.Column(db.Integer, primary_key=True)
    slug       = db.Column(db.String(50), unique=True, nullable=False)
    nombre     = db.Column(db.String(150), nullable=False)
    is_active  = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    configs      = db.relationship("TenantConfig", backref="tenant", lazy="dynamic",
                                   cascade="all, delete-orphan")
    admin_users  = db.relationship("AdminUser", backref="tenant", lazy="dynamic",
                                   cascade="all, delete-orphan")

    def get_config(self, clave: str, default=None) -> str | None:
        """Obtiene el valor de una clave de configuración del tenant."""
        cfg = self.configs.filter_by(clave=clave).first()
        return cfg.valor if cfg and cfg.valor is not None else default

    def set_config(self, clave: str, valor: str) -> None:
        cfg = self.configs.filter_by(clave=clave).first()
        if cfg:
            cfg.valor = valor
            cfg.updated_at = datetime.now(timezone.utc)
        else:
            db.session.add(TenantConfig(tenant_id=self.id, clave=clave, valor=valor))
```

### models/tenant_config.py

```python
class TenantConfig(db.Model):
    __tablename__ = "tenant_configs"
    id        = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    clave     = db.Column(db.String(100), nullable=False)
    valor     = db.Column(db.Text)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                            onupdate=lambda: datetime.now(timezone.utc))
```

### models/global_setting.py

```python
class GlobalSetting(db.Model):
    __tablename__ = "global_settings"
    clave      = db.Column(db.String(100), primary_key=True)
    valor      = db.Column(db.Text)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    @classmethod
    def get(cls, clave: str, default=None) -> str | None:
        row = cls.query.filter_by(clave=clave).first()
        return row.valor if row and row.valor is not None else default

    @classmethod
    def set(cls, clave: str, valor: str) -> None:
        row = cls.query.filter_by(clave=clave).first()
        if row:
            row.valor = valor
        else:
            db.session.add(cls(clave=clave, valor=valor))
        db.session.commit()
```

### models/admin_user.py

```python
from werkzeug.security import generate_password_hash, check_password_hash

class AdminUser(db.Model):
    __tablename__ = "admin_users"
    id         = db.Column(db.Integer, primary_key=True)
    tenant_id  = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    username   = db.Column(db.String(80), nullable=False)
    email      = db.Column(db.String(120), nullable=False)
    password   = db.Column(db.String(255), nullable=False)
    is_active  = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def set_password(self, plain: str):
        self.password = generate_password_hash(plain)

    def check_password(self, plain: str) -> bool:
        return check_password_hash(self.password, plain)
```

### models/change_history.py

```python
class ChangeHistory(db.Model):
    __tablename__ = "change_history"
    id          = db.Column(db.Integer, primary_key=True)
    tenant_id   = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    admin_id    = db.Column(db.Integer, db.ForeignKey("admin_users.id"), nullable=True)
    cedula      = db.Column(db.String(20), nullable=False)
    tipo_cambio = db.Column(db.String(20), nullable=False)
    valor_nuevo = db.Column(db.Text, nullable=False)
    ip_onu      = db.Column(postgresql.INET)
    fecha       = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
```

---

## MIDDLEWARE DE RESOLUCIÓN DE TENANT

El tenant se resuelve de forma distinta según la ruta:

- **`/{slug}/...`** → tenant leído del primer segmento de la URL
- **`/admin/...`** → tenant leído de `session['admin_tenant_id']` (quién está logueado)
- **`/superadmin/...`** → sin tenant (`g.tenant = None`)

```python
# middleware/tenant.py
from flask import g, abort, request
from models.tenant import Tenant

# Segmentos de URL que NO son slugs de tenant
SYSTEM_PATHS = {'admin', 'superadmin', 'static', 'favicon.ico', ''}

def resolve_tenant():
    """
    Resuelve g.tenant según el tipo de ruta:
      /{slug}/...   → busca el tenant por slug en BD
      /admin/...    → g.tenant = None (el decorador @admin_requerido lo carga desde sesión)
      /superadmin/  → g.tenant = None
      /             → g.tenant = None (landing general)
    """
    first_segment = request.path.strip('/').split('/')[0].lower()

    if first_segment in SYSTEM_PATHS:
        g.tenant = None
        return

    # Es una ruta de cliente → resolver tenant por slug en URL
    tenant = Tenant.query.filter_by(slug=first_segment, is_active=True).first()

    if not tenant:
        abort(404)

    g.tenant = tenant
```

### Registro en app.py

```python
# app.py
from middleware.tenant import resolve_tenant

def create_app(config_name='production'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    limiter.init_app(app)

    app.before_request(resolve_tenant)

    # Inyectar branding del tenant en templates de clientes
    @app.context_processor
    def inject_tenant():
        tenant = getattr(g, 'tenant', None)
        if tenant:
            return {
                'tenant':                   tenant,
                'empresa_nombre':           tenant.get_config('empresa_nombre', tenant.nombre),
                'empresa_logo_url':         tenant.get_config('empresa_logo_url', '/static/global/logo_default.png'),
                'empresa_color_primario':   tenant.get_config('empresa_color_primario', '#1a73e8'),
                'empresa_color_secundario': tenant.get_config('empresa_color_secundario', '#ffffff'),
                'empresa_color_texto':      tenant.get_config('empresa_color_texto', '#212121'),
            }
        return {}

    from blueprints.customers  import bp as customers_bp
    from blueprints.admin      import bp as admin_bp
    from blueprints.superadmin import bp as superadmin_bp

    # Clientes: /{slug}/  /{slug}/login  /{slug}/dashboard ...
    app.register_blueprint(customers_bp,  url_prefix='/<tenant_slug>')

    # Admin: /admin/login  /admin/dashboard  /admin/historial ...
    app.register_blueprint(admin_bp,      url_prefix='/admin')

    # SuperAdmin: /superadmin/dashboard  /superadmin/tenants ...
    app.register_blueprint(superadmin_bp, url_prefix='/superadmin')

    return app
```

### Consumir `tenant_slug` en el blueprint de clientes

El blueprint de clientes recibe `tenant_slug` como variable de URL. Se consume en el preprocessor para que no llegue como parámetro a cada función de vista (ya está en `g.tenant`):

```python
# blueprints/customers/__init__.py
from flask import Blueprint

bp = Blueprint('customers', __name__)

@bp.url_value_preprocessor
def pull_tenant_slug(endpoint, values):
    # Extrae tenant_slug de los valores de URL antes de llamar a la vista.
    # g.tenant ya fue cargado por el middleware; aquí solo lo descartamos.
    values.pop('tenant_slug', None)
```

---

## HELPERS — INSTANCIACIÓN DE SERVICIOS POR TENANT

Cada llamada a una API externa debe usar las credenciales y URL específicas del tenant activo.

```python
# helpers/tenant_services.py
from flask import g
from services.wisphub import WispHubService
from services.genieacs import GenieACService
from services.ycloud   import YCloudService
from models.global_setting import GlobalSetting

def get_wisphub(tenant=None) -> WispHubService:
    """
    Devuelve WispHubService configurado con las credenciales del tenant.
    Si no se pasa tenant, usa g.tenant.
    Lanza ValueError si las credenciales no están configuradas.
    """
    t = tenant or g.tenant
    url = t.get_config('wisphub_url')
    key = t.get_config('wisphub_api_key')
    if not url or not key:
        raise ValueError(f"Tenant '{t.slug}' no tiene WispHub configurado.")
    return WispHubService(base_url=url, api_key=key)


def get_genieacs(tenant=None) -> GenieACService:
    """
    Devuelve GenieACService con la URL del tenant.
    Lanza ValueError si no está configurada.
    """
    t = tenant or g.tenant
    url = t.get_config('genieacs_url')
    if not url:
        raise ValueError(f"Tenant '{t.slug}' no tiene GenieACS configurado.")
    return GenieACService(base_url=url)


def get_ycloud() -> YCloudService:
    """
    YCloud es global — usa GlobalSetting.
    Solo el SuperAdmin puede configurarlo.
    """
    api_key     = GlobalSetting.get('ycloud_api_key')
    sender_id   = GlobalSetting.get('ycloud_sender_id')
    from_number = GlobalSetting.get('ycloud_from_number')
    if not api_key or not from_number:
        raise ValueError("YCloud no está configurado. Configure desde el panel SuperAdmin.")
    return YCloudService(api_key=api_key, sender_id=sender_id, from_number=from_number)
```

---

## SERVICIOS — IMPLEMENTACIÓN CON INYECCIÓN DE CONFIGURACIÓN

### services/wisphub.py

```python
import requests
from requests.exceptions import RequestException

class WispHubService:
    TIMEOUT = 10  # segundos

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key  = api_key

    def _headers(self) -> dict:
        return {
            "Api-Key":      self.api_key,
            "Content-Type": "application/json"
        }

    def buscar_cliente(self, cedula: str) -> dict | None:
        """
        GET {base_url}?cedula={cedula}&estado=activo
        Headers: Api-Key: {api_key}
        Retorna el primer resultado o None.
        Campos clave en la respuesta:
          results[0].id
          results[0].nombre
          results[0].cedula
          results[0].telefono        → número WhatsApp (normalizar a E.164)
          results[0].servicios[].id
          results[0].servicios[].ip
          results[0].servicios[].estado
          results[0].servicios[].clave_wifi
          results[0].servicios[].ssid_wifi
        """
        try:
            r = requests.get(
                self.base_url,
                params={"cedula": cedula, "estado": "activo"},
                headers=self._headers(),
                timeout=self.TIMEOUT
            )
            r.raise_for_status()
            data = r.json()
            results = data.get("results", [])
            return results[0] if results else None
        except RequestException as e:
            raise RuntimeError(f"WispHub error buscando cédula {cedula}: {e}")

    def buscar_por_texto(self, q: str) -> list[dict]:
        """
        GET {base_url}?search={q}&estado=activo&page_size=20
        Para búsquedas en panel admin.
        """
        try:
            r = requests.get(
                self.base_url,
                params={"search": q, "estado": "activo", "page_size": 20},
                headers=self._headers(),
                timeout=self.TIMEOUT
            )
            r.raise_for_status()
            return r.json().get("results", [])
        except RequestException as e:
            raise RuntimeError(f"WispHub error buscando '{q}': {e}")

    def actualizar_wifi(self, servicio_id: int, ssid: str | None, clave: str | None) -> bool:
        """
        PATCH {base_url}/{servicio_id}/
        Body: solo los campos que cambian (ssid_wifi o clave_wifi)
        Retorna True si status 200 o 204.
        """
        payload = {}
        if ssid  is not None: payload['ssid_wifi']  = ssid
        if clave is not None: payload['clave_wifi'] = clave
        if not payload:
            return True
        try:
            r = requests.patch(
                f"{self.base_url}/{servicio_id}/",
                json=payload,
                headers=self._headers(),
                timeout=self.TIMEOUT
            )
            return r.status_code in (200, 204)
        except RequestException as e:
            raise RuntimeError(f"WispHub error actualizando servicio {servicio_id}: {e}")

    def listar_todos_activos(self, page_size: int = 100) -> list[dict]:
        """
        Pagina sobre {base_url}?estado=activo hasta agotar resultados.
        Usado por la herramienta de soporte (comparación de IPs).
        """
        resultados = []
        page = 1
        while True:
            try:
                r = requests.get(
                    self.base_url,
                    params={"estado": "activo", "page_size": page_size, "page": page},
                    headers=self._headers(),
                    timeout=self.TIMEOUT
                )
                r.raise_for_status()
                data = r.json()
                batch = data.get("results", [])
                resultados.extend(batch)
                if not data.get("next"):
                    break
                page += 1
            except RequestException as e:
                raise RuntimeError(f"WispHub error listando todos: {e}")
        return resultados
```

### services/genieacs.py

```python
import urllib.parse
import requests
from requests.exceptions import RequestException
from datetime import datetime, timezone, timedelta

class GenieACService:
    TIMEOUT = 10
    TASK_TIMEOUT_MS = 3000

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')

    def _encode_device_id(self, device_id: str) -> list[str]:
        """
        Genera múltiples variantes de encoding del device_id.
        GenieACS acepta IDs con caracteres especiales; probar todas las variantes.
        """
        return [
            urllib.parse.quote(device_id, safe=''),
            device_id.replace(' ', '%20'),
            device_id,
        ]

    def get_device_by_ip(self, ip: str) -> dict | None:
        """
        Estrategia 1 (optimizada):
          GET {base_url}/devices?query={"InternetGatewayDevice.WANDevice.1
            .WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress._value": "{ip}"}

        Estrategia 2 (fallback):
          GET {base_url}/devices → filtrar por IP en memoria

        Retorna el documento del dispositivo o None.
        """
        query = {"InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1"
                 ".WANIPConnection.1.ExternalIPAddress._value": ip}
        try:
            r = requests.get(
                f"{self.base_url}/devices",
                params={"query": str(query).replace("'", '"')},
                timeout=self.TIMEOUT
            )
            devices = r.json()
            if devices:
                return devices[0]
        except Exception:
            pass

        # Fallback: escanear todos
        try:
            r = requests.get(f"{self.base_url}/devices", timeout=self.TIMEOUT)
            for d in r.json():
                wan = (d.get("InternetGatewayDevice", {})
                         .get("WANDevice", {})
                         .get("1", {})
                         .get("WANConnectionDevice", {})
                         .get("1", {})
                         .get("WANIPConnection", {})
                         .get("1", {})
                         .get("ExternalIPAddress", {})
                         .get("_value", ""))
                if wan == ip:
                    return d
        except Exception:
            pass
        return None

    def get_wifi_interfaces(self, device: dict) -> list[dict]:
        """
        Parsear InternetGatewayDevice.LANDevice.*.WLANConfiguration.*
        Para cada interfaz devolver:
          {
            "path":      "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1",
            "ssid":      "MiRed",
            "channel":   6,
            "enabled":   True,
            "frequency": "2.4GHz"   # o "5GHz"
          }
        Canales 1-13 → 2.4GHz | Canales 36+ → 5GHz
        """
        interfaces = []
        lan_device = device.get("InternetGatewayDevice", {}).get("LANDevice", {})
        for lan_idx, lan in lan_device.items():
            if lan_idx.startswith("_"):
                continue
            wlan_configs = lan.get("WLANConfiguration", {})
            for wlan_idx, wlan in wlan_configs.items():
                if wlan_idx.startswith("_"):
                    continue
                enabled = wlan.get("Enable", {}).get("_value", False)
                if not enabled:
                    continue
                channel = int(wlan.get("Channel", {}).get("_value", 0) or 0)
                ssid    = wlan.get("SSID", {}).get("_value", "")
                path    = f"InternetGatewayDevice.LANDevice.{lan_idx}.WLANConfiguration.{wlan_idx}"
                frequency = "5GHz" if channel >= 36 else "2.4GHz"
                interfaces.append({
                    "path": path, "ssid": ssid,
                    "channel": channel, "enabled": True,
                    "frequency": frequency
                })
        return interfaces

    def is_online(self, device: dict, threshold_minutes: int = 5) -> bool:
        """
        Retorna True si _lastInform fue hace menos de threshold_minutes minutos.
        """
        last_inform = device.get("_lastInform")
        if not last_inform:
            return False
        if isinstance(last_inform, str):
            last_inform = datetime.fromisoformat(last_inform.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - last_inform) < timedelta(minutes=threshold_minutes)

    def set_parameter_values(self, device_id: str, params: list[tuple]) -> bool:
        """
        POST {base_url}/devices/{device_id_encoded}/tasks?connection_request_timeout=3000
        Body: {"name": "setParameterValues", "parameterValues": [[path, value, type], ...]}
        Intenta múltiples encodings del device_id.
        Retorna True si alguno tiene éxito (status 200 o 202).
        """
        body = {"name": "setParameterValues", "parameterValues": list(params)}
        for encoded_id in self._encode_device_id(device_id):
            try:
                r = requests.post(
                    f"{self.base_url}/devices/{encoded_id}/tasks",
                    params={"connection_request_timeout": self.TASK_TIMEOUT_MS},
                    json=body,
                    timeout=self.TIMEOUT + 5
                )
                if r.status_code in (200, 202):
                    return True
            except RequestException:
                continue
        return False

    def reboot_device(self, device_id: str) -> bool:
        """
        POST {base_url}/devices/{device_id_encoded}/tasks
        Body: {"name": "reboot"}
        """
        for encoded_id in self._encode_device_id(device_id):
            try:
                r = requests.post(
                    f"{self.base_url}/devices/{encoded_id}/tasks",
                    json={"name": "reboot"},
                    timeout=self.TIMEOUT
                )
                if r.status_code in (200, 202):
                    return True
            except RequestException:
                continue
        return False

    def get_all_devices(self) -> list[dict]:
        """
        GET {base_url}/devices?projection=_id,_lastInform,
            InternetGatewayDevice.WANDevice...ExternalIPAddress
        Para panel admin de dispositivos.
        """
        try:
            r = requests.get(
                f"{self.base_url}/devices",
                params={"projection": "_id,_lastInform"},
                timeout=30
            )
            r.raise_for_status()
            return r.json()
        except RequestException as e:
            raise RuntimeError(f"GenieACS error listando dispositivos: {e}")
```

### services/ycloud.py

```python
import requests
from requests.exceptions import RequestException

class YCloudService:
    BASE_URL = "https://api.ycloud.com/v2/whatsapp"
    TIMEOUT  = 10

    def __init__(self, api_key: str, sender_id: str, from_number: str):
        self.api_key     = api_key
        self.sender_id   = sender_id
        self.from_number = from_number

    def _headers(self) -> dict:
        return {"X-API-Key": self.api_key, "Content-Type": "application/json"}

    def send_otp(self, phone: str, code: str, template_name: str = "auth_skypass") -> bool:
        """
        POST {BASE_URL}/messages/sendDirectly
        Envía OTP usando el template configurado en el tenant.
        Variables del template: [code]
        El teléfono debe estar en formato E.164 (ej: 573001234567).
        """
        payload = {
            "from": self.from_number,
            "to":   phone,
            "type": "template",
            "template": {
                "name":     template_name,
                "language": {"code": "es"},
                "components": [
                    {
                        "type": "body",
                        "parameters": [{"type": "text", "text": code}]
                    },
                    {
                        "type": "button",
                        "sub_type": "url",
                        "index": "0",
                        "parameters": [{"type": "text", "text": code}]
                    }
                ]
            }
        }
        try:
            r = requests.post(
                f"{self.BASE_URL}/messages/sendDirectly",
                json=payload,
                headers=self._headers(),
                timeout=self.TIMEOUT
            )
            return r.status_code in (200, 201)
        except RequestException as e:
            raise RuntimeError(f"YCloud error enviando OTP: {e}")

    def send_change_confirmation(
        self,
        phone: str,
        nombre: str,
        tipo_cambio: str,
        nuevo_valor: str,
        template_name: str = "solicitud_cambio_skypass_v2"
    ) -> bool:
        """
        POST {BASE_URL}/messages/sendDirectly
        Variables: [nombre, tipo_cambio, valor_enmascarado]
        Enmascarar: mostrar últimos 3 chars, resto con '*'.
        Ej: "MiRedWifi" → "******ifi"
        """
        n = len(nuevo_valor)
        if n <= 3:
            mascara = "*" * n
        else:
            mascara = "*" * (n - 3) + nuevo_valor[-3:]

        payload = {
            "from": self.from_number,
            "to":   phone,
            "type": "template",
            "template": {
                "name":     template_name,
                "language": {"code": "es"},
                "components": [
                    {
                        "type": "body",
                        "parameters": [
                            {"type": "text", "text": nombre},
                            {"type": "text", "text": tipo_cambio},
                            {"type": "text", "text": mascara}
                        ]
                    }
                ]
            }
        }
        try:
            r = requests.post(
                f"{self.BASE_URL}/messages/sendDirectly",
                json=payload,
                headers=self._headers(),
                timeout=self.TIMEOUT
            )
            return r.status_code in (200, 201)
        except RequestException as e:
            raise RuntimeError(f"YCloud error enviando confirmación: {e}")

    def get_connection_status(self) -> dict:
        """
        GET {BASE_URL}/phoneNumbers
        Retorna el estado de conexión del número de WhatsApp.
        """
        try:
            r = requests.get(
                f"{self.BASE_URL}/phoneNumbers",
                headers=self._headers(),
                timeout=self.TIMEOUT
            )
            r.raise_for_status()
            return r.json()
        except RequestException as e:
            raise RuntimeError(f"YCloud error verificando estado: {e}")
```

### services/otp.py

```python
import random
from datetime import datetime, timezone, timedelta
from extensions import db
from models.otp import OTP
from models.ip_block import IPBlock

class OTPService:
    TTL_MINUTOS      = 5
    MAX_INTENTOS     = 3
    BLOQUEO_MINUTOS  = 2

    def __init__(self, tenant_id: int):
        self.tenant_id = tenant_id

    def generar(self, cedula: str) -> str:
        """
        Genera OTP de 6 dígitos y lo guarda en la tabla otps.
        Usa UPSERT para reemplazar cualquier OTP anterior de la misma cédula.
        """
        code       = str(random.randint(100000, 999999))
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.TTL_MINUTOS)

        existing = OTP.query.filter_by(tenant_id=self.tenant_id, cedula=cedula).first()
        if existing:
            existing.codigo     = code
            existing.intentos   = 0
            existing.expires_at = expires_at
        else:
            db.session.add(OTP(
                tenant_id=self.tenant_id,
                cedula=cedula,
                codigo=code,
                intentos=0,
                expires_at=expires_at
            ))
        db.session.commit()
        return code

    def verificar(self, cedula: str, codigo: str) -> tuple[bool, str]:
        """
        Verifica el OTP. Retorna (exito, mensaje).
        Casos:
          - No existe o expiró → (False, "Código expirado")
          - Intentos >= MAX → (False, "Demasiados intentos")
          - Código incorrecto → incrementa intentos, (False, "Código incorrecto")
          - Correcto → elimina el registro, (True, "OK")
        """
        otp = OTP.query.filter_by(tenant_id=self.tenant_id, cedula=cedula).first()

        if not otp or otp.expires_at < datetime.now(timezone.utc):
            if otp:
                db.session.delete(otp)
                db.session.commit()
            return False, "Código expirado. Solicita uno nuevo."

        if otp.intentos >= self.MAX_INTENTOS:
            return False, "Demasiados intentos. Espera 2 minutos."

        if otp.codigo != codigo.strip():
            otp.intentos += 1
            db.session.commit()
            restantes = self.MAX_INTENTOS - otp.intentos
            return False, f"Código incorrecto. Te quedan {restantes} intento(s)."

        db.session.delete(otp)
        db.session.commit()
        return True, "OK"

    def bloquear_ip(self, ip: str, accion: str) -> None:
        """
        Guarda un bloqueo de IP en la tabla ip_blocks con tiempo de expiración.
        Usa UPSERT para actualizar si ya existe.
        """
        hasta = datetime.now(timezone.utc) + timedelta(minutes=self.BLOQUEO_MINUTOS)
        existing = IPBlock.query.filter_by(
            tenant_id=self.tenant_id, ip=ip, accion=accion
        ).first()
        if existing:
            existing.bloqueado_hasta = hasta
        else:
            db.session.add(IPBlock(
                tenant_id=self.tenant_id,
                ip=ip,
                accion=accion,
                bloqueado_hasta=hasta
            ))
        db.session.commit()

    def esta_bloqueada_ip(self, ip: str, accion: str) -> bool:
        """
        Retorna True si existe un bloqueo vigente para la IP y acción dadas.
        """
        block = IPBlock.query.filter_by(
            tenant_id=self.tenant_id, ip=ip, accion=accion
        ).first()
        if not block:
            return False
        if block.bloqueado_hasta < datetime.now(timezone.utc):
            db.session.delete(block)
            db.session.commit()
            return False
        return True

    @staticmethod
    def limpiar_expirados() -> None:
        """
        Elimina OTPs e IPBlocks vencidos. Llamar en before_request o tarea periódica.
        """
        ahora = datetime.now(timezone.utc)
        OTP.query.filter(OTP.expires_at < ahora).delete()
        IPBlock.query.filter(IPBlock.bloqueado_hasta < ahora).delete()
        db.session.commit()
```

### Modelos para las nuevas tablas

```python
# models/otp.py
class OTP(db.Model):
    __tablename__ = "otps"
    id          = db.Column(db.Integer, primary_key=True)
    tenant_id   = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    cedula      = db.Column(db.String(20), nullable=False)
    codigo      = db.Column(db.String(6), nullable=False)
    intentos    = db.Column(db.Integer, default=0, nullable=False)
    expires_at  = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (db.UniqueConstraint('tenant_id', 'cedula'),)

# models/ip_block.py
class IPBlock(db.Model):
    __tablename__ = "ip_blocks"
    id              = db.Column(db.Integer, primary_key=True)
    tenant_id       = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=True)
    ip              = db.Column(db.String(45), nullable=False)
    accion          = db.Column(db.String(50), nullable=False)
    bloqueado_hasta = db.Column(db.DateTime(timezone=True), nullable=False)
    __table_args__ = (db.UniqueConstraint('tenant_id', 'ip', 'accion'),)
```

---

## FLUJO COMPLETO DE AUTENTICACIÓN DE CLIENTES (TENANT-AWARE)

### Paso 1 — Login (GET/POST `/`)

```
1. Middleware ya resolvió g.tenant (o 404)
2. GET → renderizar landing page / login con branding del tenant
3. POST → recibir cedula del form
4. Verificar bloqueo de IP en BD:
   otp_svc = OTPService(g.tenant.id)
   Si otp_svc.esta_bloqueada_ip(ip, 'login') → error con tiempo restante
5. Obtener servicio WispHub del tenant:
   wisphub = get_wisphub(g.tenant)  ← URL y API Key del tenant desde BD
6. cliente = wisphub.buscar_cliente(cedula)
7. Si no existe → contar intento en sesión Flask → error
8. Si intentos >= 3 → otp_svc.bloquear_ip(ip, 'login') → error
9. Normalizar teléfono a E.164:
   telefono = normalizar_telefono(cliente['telefono'])
10. Generar OTP y guardarlo en tabla otps:
    code = otp_svc.generar(cedula)
11. Enviar OTP vía YCloud global:
    ycloud = get_ycloud()  ← credenciales desde GlobalSetting
    template = g.tenant.get_config('whatsapp_template_otp', 'auth_skypass')
    ycloud.send_otp(telefono, code, template)
12. Guardar en sesión:
    session['tenant_slug']      = g.tenant.slug
    session['cedula_pendiente'] = cedula
    session['telefono_masked']  = telefono[-4:]   # últimos 4 dígitos
13. Redirigir a /otp
```

### Paso 2 — Verificación OTP (POST `/verificar_codigo_ajax`)

```
Request JSON: {"codigo": "123456"}

1. Verificar g.tenant activo y session['tenant_slug'] coincide
2. otp_svc = OTPService(g.tenant.id)
3. ok, msg = otp_svc.verificar(session['cedula_pendiente'], codigo)
4. Si no ok → retornar {"ok": false, "error": msg}
5. Si ok:
   - Cargar servicios activos del cliente desde WispHub
   - Si 1 servicio:
       Crear sesión completa:
       session['cliente_encontrado'] = True
       session['cedula']   = cedula
       session['ip_onu']   = servicios[0]['ip']
       session['servicio_id'] = servicios[0]['id']
       session['nombre']   = cliente['nombre']
       session['telefono'] = telefono
       Retornar {"ok": true, "redirigir": "/dashboard"}
   - Si > 1 servicio:
       session['servicios_disponibles'] = lista_de_servicios
       Retornar {"ok": true, "redirigir": "/seleccionar_servicio"}
```

### Paso 3 — Selección de servicio (POST `/seleccionar_servicio`)

```
1. Recibir ip y servicio_id seleccionados
2. Validar que están en session['servicios_disponibles']
3. session['ip_onu']      = ip
   session['servicio_id'] = servicio_id
4. Redirigir a /dashboard
```

---

## FLUJO CAMBIO DE CONTRASEÑA WIFI (TENANT-AWARE)

**Rutas:** `GET/POST /cambiar_clave` — protegida con `@cliente_requerido`

### Sub-acción `validar_dispositivo`

```
1. genieacs = get_genieacs(g.tenant)  ← URL del tenant desde BD
2. device = genieacs.get_device_by_ip(session['ip_onu'])
3. online = genieacs.is_online(device) si device else False
4. Retornar {"online": online, "ultima_conexion": "..."}
```

### Sub-acción `whatsapp`

```
1. Recibir nueva_clave
2. Validar: len >= 8, sin chars de control (ord < 32)
3. Verificar límite mensual:
   limite = obtener_limite(g.tenant, session['cedula'], session['ip_onu'])
   cambios = contar_cambios_mes(g.tenant.id, session['cedula'])
   Si cambios >= limite → error "Límite mensual alcanzado"
4. Enviar confirmación WhatsApp:
   ycloud = get_ycloud()
   template = g.tenant.get_config('whatsapp_template_confirmacion',
                                   'solicitud_cambio_skypass_v2')
   ycloud.send_change_confirmation(
       session['telefono'], session['nombre'],
       "Contraseña WiFi", nueva_clave, template
   )
5. session['nueva_clave_pendiente'] = nueva_clave
6. Retornar {"ok": true}
```

### Sub-acción `cambiar`

```
1. nueva_clave = session.pop('nueva_clave_pendiente')
2. genieacs = get_genieacs(g.tenant)  ← URL específica del tenant
3. device = genieacs.get_device_by_ip(session['ip_onu'])
4. device_id = device['_id']
5. interfaces = genieacs.get_wifi_interfaces(device)
6. Para cada interfaz:
   params = [
     (f"{iface['path']}.KeyPassphrase",              nueva_clave, "xsd:string"),
     (f"{iface['path']}.PreSharedKey.1.PreSharedKey", nueva_clave, "xsd:string"),
   ]
   genieacs.set_parameter_values(device_id, params)
7. genieacs.reboot_device(device_id)
8. Registrar en change_history (tenant_id = g.tenant.id):
   INSERT INTO change_history (tenant_id, cedula, tipo_cambio, valor_nuevo, ip_onu)
   VALUES (g.tenant.id, cedula, 'Password', nueva_clave, ip_onu)
9. Incrementar change_limits:
   INSERT INTO change_limits (tenant_id, cedula, mes_anio, cambios_realizados)
   VALUES (g.tenant.id, cedula, 'YYYY-MM', 1)
   ON CONFLICT (tenant_id, cedula, mes_anio)
   DO UPDATE SET cambios_realizados = change_limits.cambios_realizados + 1
10. Actualizar WispHub del tenant:
    wisphub = get_wisphub(g.tenant)
    wisphub.actualizar_wifi(session['servicio_id'], ssid=None, clave=nueva_clave)
11. Retornar {"ok": true, "mensaje": "Contraseña actualizada correctamente."}
```

---

## FLUJO CAMBIO DE SSID (TENANT-AWARE)

### Sub-acción `cambiar`

```
1. nuevo_ssid = form['nuevo_ssid']
2. Validar: 1-32 chars, solo ASCII imprimibles
3. Verificar límite mensual (igual que cambio de clave)
4. genieacs = get_genieacs(g.tenant)
5. Obtener interfaces WiFi del dispositivo
6. Para cada interfaz:
   - Si hay interfaces de ambas frecuencias:
       2.4GHz: ssid_aplicar = f"{nuevo_ssid}-2.4GHz"
       5GHz:   ssid_aplicar = f"{nuevo_ssid}-5GHz"
   - Si solo hay una frecuencia:
       ssid_aplicar = nuevo_ssid (sin sufijo)
   params = [(f"{iface['path']}.SSID", ssid_aplicar, "xsd:string")]
   genieacs.set_parameter_values(device_id, params)
7. genieacs.reboot_device(device_id)  (una sola vez al final)
8. Registrar en change_history (tenant_id)
9. Incrementar change_limits (tenant_id)
10. Actualizar WispHub del tenant con nuevo SSID base (sin sufijo)
```

---

## PANEL ADMIN POR TENANT

Prefijo: `/admin` — protegido por `@admin_requerido`

### Login único `/admin/login`

Un solo formulario para todos. El sistema detecta el tipo de usuario y redirige:

```python
# blueprints/admin/routes.py

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('admin/admin_login.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    # 1. Verificar si es SuperAdmin
    sa = SuperAdmin.query.filter_by(username=username, is_active=True).first()
    if sa and sa.check_password(password):
        session.clear()
        session['sa_autenticado']  = True
        session['sa_id']           = sa.id
        session['sa_username']     = sa.username
        return redirect(url_for('superadmin.dashboard'))

    # 2. Verificar si es Admin de tenant
    admin = AdminUser.query.filter_by(username=username, is_active=True).first()
    if admin and admin.check_password(password):
        session.clear()
        session['admin_autenticado'] = True
        session['admin_id']          = admin.id
        session['admin_tenant_id']   = admin.tenant_id
        session['admin_username']    = admin.username
        return redirect(url_for('admin.dashboard'))

    # 3. Credenciales incorrectas
    flash('Usuario o contraseña incorrectos.', 'error')
    return render_template('admin/admin_login.html')
```

### Decorador `@admin_requerido`

```python
# blueprints/admin/decorators.py
from functools import wraps
from flask import session, redirect, url_for, g
from models.admin_user import AdminUser
from models.tenant import Tenant

def admin_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_autenticado'):
            return redirect(url_for('admin.login'))

        # Cargar tenant del admin desde sesión (no desde URL)
        tenant = Tenant.query.get(session.get('admin_tenant_id'))
        if not tenant or not tenant.is_active:
            session.clear()
            return redirect(url_for('admin.login'))

        # Verificar que el admin aún existe y está activo
        admin = AdminUser.query.filter_by(
            id=session['admin_id'], tenant_id=tenant.id, is_active=True
        ).first()
        if not admin:
            session.clear()
            return redirect(url_for('admin.login'))

        g.tenant = tenant   # disponible en toda la vista
        g.admin  = admin
        return f(*args, **kwargs)
    return decorated
```

### Rutas del panel admin por tenant

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET/POST | `/admin/login` | **Login único** para admins de ISP y SuperAdmin |
| POST | `/admin/logout` | Cerrar sesión |
| GET | `/admin/dashboard` | Panel: resumen cambios del mes, estado WhatsApp global, accesos rápidos |
| GET | `/admin/historial` | Historial paginado filtrado por tenant_id. Filtros: cedula, tipo, fecha |
| GET | `/admin/estadisticas` | JSON: cambios por tipo y por mes, solo del tenant |
| GET | `/admin/limites` | Ver límites personalizados por IP (solo del tenant) |
| POST | `/admin/buscar_cliente_limite` | Buscar cliente por IP o cédula (WispHub del tenant) |
| POST | `/admin/editar_limite` | Actualizar limite_personalizado en user_limits (tenant_id) |
| POST | `/admin/eliminar_limite` | Poner limite_personalizado = NULL |
| GET | `/admin/configuracion` | Ver configuración del tenant (WispHub URL/Key, GenieACS URL, max_cambios_mes, branding) |
| POST | `/admin/cambiar_config` | Actualizar tenant_configs: wisphub_url, wisphub_api_key, genieacs_url, max_cambios_mes |
| POST | `/admin/cambiar_branding` | Actualizar empresa_nombre, logo, colores en tenant_configs |
| POST | `/admin/cambiar_password` | Cambiar password del admin autenticado |
| GET | `/admin/cambiar_wifi_cliente` | Buscar cliente y cambiar WiFi manualmente desde admin |
| POST | `/admin/cambiar_wifi_cliente` | AJAX: ejecutar cambio (usa WispHub + GenieACS del tenant) |
| GET | `/admin/buscar_cliente` | Formulario de búsqueda de clientes |
| POST | `/admin/api/buscar_clientes` | AJAX: busca en WispHub del tenant |
| GET | `/admin/dispositivos_conectados` | Vista de ONUs activas |
| POST | `/admin/api/dispositivos_conectados` | AJAX: lista desde GenieACS del tenant |
| POST | `/admin/eliminar_device` | Elimina dispositivo de GenieACS del tenant |
| POST | `/admin/eliminar_cambio_historial` | Elimina entrada de historial del tenant |
| GET | `/admin/soporte` | Comparación de IPs WispHub vs GenieACS del tenant |
| GET | `/admin/api/soporte_ips` | AJAX: resultado de comparación (caché 30s) |
| POST | `/admin/verificar-sesion` | Check AJAX de sesión activa |
| POST | `/admin/renovar-sesion` | Renovar sesión admin |

### Página de configuración del tenant (admin)

El admin puede ver y editar (si tiene permisos):

```
┌─────────────────────────────────────────────────┐
│  CONFIGURACIÓN — Mi ISP S.A.                    │
├─────────────────────────────────────────────────┤
│  INTEGRACIÓN WISPHUB                            │
│  URL API:    [https://api.wisphub.io/api/...]   │
│  API Key:    [••••••••••••••  ] [Mostrar]       │
│  [Probar conexión]                              │
├─────────────────────────────────────────────────┤
│  INTEGRACIÓN GENIEACS                           │
│  URL:        [http://192.168.1.10:7557         ]│
│  [Probar conexión]                              │
├─────────────────────────────────────────────────┤
│  LÍMITES DE CAMBIOS                             │
│  Máximo mensual global: [2]                     │
├─────────────────────────────────────────────────┤
│  BRANDING                                       │
│  Nombre empresa: [Mi ISP S.A.              ]    │
│  Logo URL:       [/static/tenants/...      ]    │
│  Color primario: [#1a73e8] ████                 │
│  Color secundario: [#ffffff] ████               │
└─────────────────────────────────────────────────┘
```

**Nota:** La configuración de WhatsApp (YCloud) NO aparece aquí. Solo el SuperAdmin puede verla y editarla.

---

## PANEL SUPERADMIN

Prefijo de rutas: `/superadmin` — protegido por `@superadmin_requerido`.  
El SuperAdmin **no tiene login propio** — entra por el mismo `/admin/login` y el sistema lo redirige aquí automáticamente.

### Decorador `@superadmin_requerido`

```python
# blueprints/superadmin/decorators.py
from functools import wraps
from flask import session, redirect, url_for, g
from models.super_admin import SuperAdmin

def superadmin_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('sa_autenticado'):
            return redirect(url_for('admin.login'))

        sa = SuperAdmin.query.filter_by(
            id=session.get('sa_id'), is_active=True
        ).first()
        if not sa:
            session.clear()
            return redirect(url_for('admin.login'))

        g.super_admin = sa
        g.tenant      = None  # SuperAdmin no tiene tenant propio
        return f(*args, **kwargs)
    return decorated
```

### Rutas del panel SuperAdmin

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/superadmin/logout` | Cerrar sesión |
| GET | `/superadmin/dashboard` | Resumen: tenants activos, cambios totales del mes, estado WhatsApp |
| GET | `/superadmin/tenants` | Lista de todos los tenants con estado |
| GET | `/superadmin/tenants/nuevo` | Formulario crear tenant |
| POST | `/superadmin/tenants/nuevo` | Crear tenant + admin inicial + configs por defecto |
| GET | `/superadmin/tenants/{id}/editar` | Editar tenant (slug, nombre, is_active) |
| POST | `/superadmin/tenants/{id}/editar` | Guardar cambios del tenant |
| POST | `/superadmin/tenants/{id}/desactivar` | Desactivar tenant (is_active = False) |
| POST | `/superadmin/tenants/{id}/activar` | Reactivar tenant |
| GET | `/superadmin/tenants/{id}/config` | Ver/editar configuración completa del tenant |
| POST | `/superadmin/tenants/{id}/config` | Guardar configuración del tenant (todas las claves) |
| GET | `/superadmin/configuracion` | Configuración global: YCloud API Key, Sender ID, From Number |
| POST | `/superadmin/configuracion` | Guardar global_settings |
| GET | `/superadmin/estadisticas` | Estadísticas globales cross-tenant |
| GET | `/superadmin/historial` | Historial global (todos los tenants) |
| POST | `/superadmin/cambiar_password` | Cambiar password del superadmin |
| POST | `/superadmin/verificar-sesion` | Check sesión |
| POST | `/superadmin/renovar-sesion` | Renovar sesión |

### Formulario de creación de tenant

```
POST /superadmin/tenants/nuevo
Body:
  slug              → "misp1"          (se convierte a minúsculas, solo a-z0-9-)
  nombre            → "Mi ISP S.A."
  wisphub_url       → "https://api.wisphub.io/api/clientes"
  wisphub_api_key   → "Token abc..."
  genieacs_url      → "http://192.168.1.10:7557"
  max_cambios_mes   → "2"
  empresa_nombre    → "Mi ISP S.A."
  empresa_color     → "#1a73e8"
  admin_username    → "admin"
  admin_email       → "admin@misp1.com"
  admin_password    → "Admin1234!"

Lógica:
1. Validar que slug no existe y no está en RESERVED_SLUGS
2. Crear Tenant (slug, nombre)
3. Crear TenantConfig para cada clave recibida
4. Crear AdminUser (tenant_id, username, email, password hasheado)
5. Retornar con mensaje de éxito y URL del tenant: https://{slug}.skypass.com
```

### Configuración global (YCloud)

```
POST /superadmin/configuracion
Body:
  ycloud_api_key     → "TU_KEY"
  ycloud_sender_id   → "TU_SENDER_ID"
  ycloud_from_number → "573127313737"

Lógica:
  Para cada campo no vacío:
    GlobalSetting.set(clave, valor)
```

---

## LANDING PAGE POR TENANT

**Ruta:** `GET /` — sin autenticación, renderiza la landing page del tenant.

La landing page usa las variables del `context_processor`:
- `empresa_nombre` → nombre de la empresa
- `empresa_logo_url` → logo
- `empresa_color_primario` → color del botón de acción
- `empresa_color_secundario` → fondo

```html
<!-- templates/landing/index.html -->
{% extends "base_tenant.html" %}

{% block content %}
<div class="landing-hero" style="background: {{ empresa_color_primario }}">
    <img src="{{ empresa_logo_url }}" alt="{{ empresa_nombre }}" class="logo-hero">
    <h1>Portal WiFi — {{ empresa_nombre }}</h1>
    <p>Cambia el nombre y contraseña de tu red WiFi de forma rápida y segura.</p>
    <a href="{{ url_for('customers.login', tenant_slug=tenant.slug) }}" class="btn-primary">Ingresar con tu cédula</a>
</div>

<section class="features">
    <div class="feature-card">
        <h3>Cambiar Contraseña</h3>
        <p>Actualiza la clave de tu red WiFi en segundos.</p>
    </div>
    <div class="feature-card">
        <h3>Cambiar Nombre de Red</h3>
        <p>Personaliza el SSID de tu red.</p>
    </div>
    <div class="feature-card">
        <h3>Verificación Segura</h3>
        <p>Confirmamos tu identidad por WhatsApp.</p>
    </div>
</section>
{% endblock %}
```

### Template base del tenant (base_tenant.html)

```html
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}{{ empresa_nombre }}{% endblock %}</title>
    <link rel="icon" href="{{ empresa_logo_url }}">
    <link rel="stylesheet" href="/static/global/styles.css">
    <style>
        :root {
            --color-primario:    {{ empresa_color_primario }};
            --color-secundario: {{ empresa_color_secundario }};
            --color-texto:      {{ empresa_color_texto }};
        }
    </style>
</head>
<body>
    <header>
        <img src="{{ empresa_logo_url }}" alt="{{ empresa_nombre }}" class="logo-header">
        <span class="empresa-nombre">{{ empresa_nombre }}</span>
    </header>
    <main>{% block content %}{% endblock %}</main>
    <div id="session-warning" style="display:none">
        Tu sesión expirará en <span id="countdown">10</span> segundos.
        <button onclick="renovarSesion()">Continuar</button>
    </div>
    <script src="/static/global/session-timeout.js"></script>
</body>
</html>
```

---

## GESTIÓN DE LÍMITES (TENANT-AWARE)

```python
def obtener_limite(tenant: Tenant, cedula: str, ip_onu: str) -> int:
    """
    Prioridad:
    1. user_limits.limite_personalizado WHERE tenant_id=X AND ip=ip_onu (no NULL)
    2. tenant.get_config('max_cambios_mes', '2')
    3. Default: 2
    """
    ul = UserLimit.query.filter_by(tenant_id=tenant.id, ip=ip_onu).first()
    if ul and ul.limite_personalizado is not None:
        return ul.limite_personalizado
    return int(tenant.get_config('max_cambios_mes', '2'))


def contar_cambios_mes(tenant_id: int, cedula: str) -> int:
    """
    SELECT cambios_realizados FROM change_limits
    WHERE tenant_id = :tid AND cedula = :c AND mes_anio = TO_CHAR(NOW(), 'YYYY-MM')
    """
    from datetime import datetime
    mes_anio = datetime.now().strftime('%Y-%m')
    cl = ChangeLimit.query.filter_by(
        tenant_id=tenant_id, cedula=cedula, mes_anio=mes_anio
    ).first()
    return cl.cambios_realizados if cl else 0


def incrementar_cambio(tenant_id: int, cedula: str) -> None:
    """
    INSERT INTO change_limits (tenant_id, cedula, mes_anio, cambios_realizados)
    VALUES (:tid, :c, :m, 1)
    ON CONFLICT (tenant_id, cedula, mes_anio)
    DO UPDATE SET cambios_realizados = change_limits.cambios_realizados + 1,
                  updated_at = NOW()
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    mes_anio = datetime.now().strftime('%Y-%m')
    stmt = pg_insert(ChangeLimit).values(
        tenant_id=tenant_id, cedula=cedula,
        mes_anio=mes_anio, cambios_realizados=1
    ).on_conflict_do_update(
        index_elements=['tenant_id', 'cedula', 'mes_anio'],
        set_={'cambios_realizados': ChangeLimit.cambios_realizados + 1,
              'updated_at': datetime.now(timezone.utc)}
    )
    db.session.execute(stmt)
    db.session.commit()
```

---

## MANEJO DE SESIONES MULTI-TENANT

```python
# Configuración Flask
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)
app.config['SESSION_COOKIE_SECURE']   = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Sesión de cliente
session = {
    'tenant_slug':        'misp1',           # identificar a qué tenant pertenece
    'cliente_encontrado': True,
    'cedula':             '1234567890',
    'ip_onu':             '192.168.1.100',
    'servicio_id':        42,               # ID del servicio en WispHub
    'nombre':             'Juan Pérez',
    'telefono':           '573001234567',
}

# Sesión de admin de tenant
session = {
    'admin_autenticado': True,
    'admin_id':          1,
    'admin_username':    'admin',
    'admin_tenant_id':   5,               # el decorador @admin_requerido carga g.tenant desde este ID
}

# Sesión de superadmin
session = {
    'sa_autenticado': True,
    'sa_id':          1,
    'sa_username':    'superadmin',
}
```

**Regla crítica de seguridad:** El tenant del admin se carga SIEMPRE desde `session['admin_tenant_id']`, nunca desde la URL. Como el panel admin no tiene slug en la URL (`/admin/dashboard`), no hay forma de que un admin cambie de tenant simplemente modificando la ruta.

---

## HERRAMIENTA DE SOPORTE (TENANT-AWARE)

```python
# blueprints/admin/routes.py
import time

# Caché en memoria por proceso: {tenant_id: (timestamp, resultado)}
_soporte_cache: dict = {}
_CACHE_TTL = 30  # segundos

@bp.get('/api/soporte_ips')
@admin_requerido
def soporte_ips():
    """
    Compara IPs activas en WispHub del tenant con IPs reportadas en GenieACS del tenant.
    Caché en memoria con TTL de 30s por tenant (suficiente para esta operación puntual).
    """
    tid   = g.tenant.id
    ahora = time.monotonic()

    if tid in _soporte_cache:
        ts, resultado = _soporte_cache[tid]
        if ahora - ts < _CACHE_TTL:
            return jsonify(resultado)

    wisphub  = get_wisphub(g.tenant)
    genieacs = get_genieacs(g.tenant)

    clientes_wh = wisphub.listar_todos_activos()
    ips_wisphub = {
        s['ip']: {'nombre': c['nombre'], 'cedula': c['cedula']}
        for c in clientes_wh
        for s in c.get('servicios', [])
        if s.get('ip') and s.get('estado') == 'activo'
    }

    dispositivos = genieacs.get_all_devices()
    ips_genieacs = {}
    for d in dispositivos:
        ip = (d.get("InternetGatewayDevice", {})
                .get("WANDevice", {}).get("1", {})
                .get("WANConnectionDevice", {}).get("1", {})
                .get("WANIPConnection", {}).get("1", {})
                .get("ExternalIPAddress", {}).get("_value", ""))
        if ip:
            ips_genieacs[ip] = {"device_id": d["_id"],
                                "ultima_conexion": str(d.get("_lastInform", ""))}

    resultado = {
        "solo_wisphub":  [{"ip": ip, **data} for ip, data in ips_wisphub.items()
                          if ip not in ips_genieacs],
        "solo_genieacs": [{"ip": ip, **data} for ip, data in ips_genieacs.items()
                          if ip not in ips_wisphub],
        "total_wisphub":  len(ips_wisphub),
        "total_genieacs": len(ips_genieacs),
    }

    _soporte_cache[tid] = (ahora, resultado)
    return jsonify(resultado)
```

---

## VARIABLES DE ENTORNO (.env.example)

Solo contiene configuración de infraestructura. **Ninguna credencial de tenant va en .env** — todo se gestiona desde la BD via SuperAdmin.

```env
# Flask
SECRET_KEY=cambia_esto_por_clave_segura_larga_y_aleatoria
FLASK_ENV=production

# PostgreSQL
DATABASE_URL=postgresql://skypass_user:password@localhost:5432/skypass_db

# Servidor
PORT=8000
```

---

## DESPLIEGUE EN EASYPANEL

EasyPanel es el proxy y gestor de contenedores. Al usar rutas (`/empresa`) en lugar de subdominios, **la configuración es mínima** — un solo dominio, SSL estándar, sin wildcards.

### Pasos en EasyPanel

**1. Crear el proyecto** — nuevo proyecto llamado `skypass`.

**2. Agregar servicio App** — apunta al repositorio Git o imagen Docker. En la sección **Domains** agregar solo:
```
skypass.com
```
EasyPanel genera el SSL automáticamente con Let's Encrypt.

**3. Agregar servicio PostgreSQL** — EasyPanel crea la BD y entrega la `DATABASE_URL` interna.

**4. Variables de entorno** en la sección Environment del servicio App:
```
SECRET_KEY=clave_segura_aleatoria
FLASK_ENV=production
DATABASE_URL=postgresql://...  (la que da EasyPanel al crear PostgreSQL)
PORT=8000
```

**5. Listo.** No hay que configurar Nginx, ni DNS wildcard, ni certificados manuales.

```
Nuevo tenant "misp2" creado en SuperAdmin:
  skypass.com/misp2  → funciona de inmediato ✓
  No tocar EasyPanel ✓
  No tocar DNS ✓
  Solo existe en la BD ✓
```

---

## DOCKER / DOCKER-COMPOSE

### Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", \
     "--workers=1", \
     "--bind=0.0.0.0:8000", \
     "--access-logfile=-", \
     "--error-logfile=-", \
     "--timeout=120", \
     "--forwarded-allow-ips=*", \
     "app:create_app()"]
```

> **Nota:** Se usa `--workers=1` porque Flask-Limiter usa backend en memoria. Si se necesitan más workers en el futuro, cambiar `storage_uri` a PostgreSQL en Flask-Limiter.

### docker-compose.yml (desarrollo local)

```yaml
version: "3.9"
services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB:       skypass_db
      POSTGRES_USER:     skypass_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U skypass_user -d skypass_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  web:
    build: .
    env_file: .env
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8000:8000"
    volumes:
      - ./static/tenants:/app/static/tenants  # logos de tenants persistentes

volumes:
  pgdata:
```

---

## REQUIREMENTS.TXT

```
Flask==3.1.0
Flask-SQLAlchemy==3.1.1
Flask-Migrate==4.0.7
Flask-Limiter==3.8.0
alembic==1.13.1
psycopg2-binary==2.9.9
SQLAlchemy==2.0.31
werkzeug==3.0.3
python-dotenv==1.0.1
requests==2.32.3
gunicorn==22.0.0
```

---

## INICIALIZACIÓN DE BASE DE DATOS

```python
# init_db.py
def init_db():
    """
    1. db.create_all() — crea todas las tablas
    2. Insertar superadmin por defecto si no existe:
         username: superadmin
         password: SuperAdmin1234! (hasheado)
         email: superadmin@skypass.com
    3. Insertar global_settings por defecto:
         ycloud_api_key    = NULL
         ycloud_sender_id  = NULL
         ycloud_from_number = NULL
         app_nombre        = 'SkyPass'
    Ejecutar: flask db upgrade (Alembic para producción)
    """
```

---

## SEGURIDAD — RESUMEN COMPLETO

### Headers en todas las respuestas

```python
@app.after_request
def security_headers(response):
    response.headers['Cache-Control']           = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma']                  = 'no-cache'
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['Referrer-Policy']         = 'no-referrer'
    response.headers['Permissions-Policy']      = 'geolocation=(), microphone=()'
    return response
```

### Validaciones de entrada

- **Cédula**: Solo dígitos, 5-15 caracteres
- **OTP**: Exactamente 6 dígitos
- **Password WiFi**: 8-63 caracteres, sin chars de control (ord < 32)
- **SSID**: 1-32 caracteres ASCII imprimibles
- **Slug de tenant**: Solo `[a-z0-9-]`, no en RESERVED_SLUGS, máx 50 chars
- **Colores HEX**: Regex `^#[0-9A-Fa-f]{6}$`
- **URLs de API**: Deben ser HTTP/HTTPS válidas
- **API Keys**: No vacías, al menos 10 caracteres

### Aislamiento de datos por tenant

- **TODA** consulta a `change_history`, `change_limits`, `user_limits`, `admin_users` incluye `WHERE tenant_id = g.tenant.id`
- El decorador `@admin_requerido` carga `g.tenant` desde `session['admin_tenant_id']`, nunca desde la URL
- Los servicios WispHub y GenieACS se instancian con las credenciales del tenant, nunca con variables globales

### Rate limiting por tenant

Flask-Limiter se configura con backend en **memoria** (no necesita Redis). Funciona correctamente con **1 worker** de Gunicorn (ver nota en Docker).

```python
# extensions.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import g

limiter = Limiter(
    key_func=lambda: f"{getattr(g, 'tenant', None) and g.tenant.slug}:{get_remote_address()}",
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://"   # sin Redis, estado en RAM del proceso
)
```

El bloqueo por intentos fallidos de login/OTP **no** usa Flask-Limiter — se gestiona directamente con la tabla `ip_blocks` en PostgreSQL, lo que garantiza persistencia aunque el proceso se reinicie.

---

## NOTAS CRÍTICAS DE IMPLEMENTACIÓN

1. **Aislamiento de datos:** Cada query a tablas con `tenant_id` DEBE filtrar por `g.tenant.id`. Un WHERE faltante es una brecha crítica de seguridad entre tenants.

2. **Tenant del admin viene de la sesión, no de la URL.** El panel admin no tiene slug en la URL (`/admin/dashboard`). El tenant se carga desde `session['admin_tenant_id']`. Esto hace imposible que un admin cambie de tenant modificando la URL.

3. **Login único para admin y superadmin.** La ruta `/admin/login` primero busca en `super_admins`, luego en `admin_users`. El orden importa: verificar superadmin primero para evitar colisiones de username.

4. **Credenciales de tenant en BD.** Las API keys de WispHub y GenieACS se guardan en `tenant_configs`. Se recomienda cifrarlas con Fernet (`cryptography` lib) usando `SECRET_KEY` como master key, y descifrarlas solo al instanciar el servicio.

5. **YCloud es global — una cuenta para todos los tenants.** Solo el SuperAdmin puede modificar estas credenciales. Los templates de WhatsApp son configurables por tenant para que cada ISP use su propio nombre en los mensajes.

6. **Slugs reservados.** La lista `SYSTEM_PATHS = {'admin', 'superadmin', 'static', 'favicon.ico', ''}` se valida al crear un tenant. Un slug como `admin` o `superadmin` rompería el enrutamiento.

7. **Device ID en GenieACS.** Los IDs contienen caracteres especiales. Probar siempre 3 encodings. El error más frecuente es un 404 por encoding incorrecto del ID.

8. **Teléfono E.164.** El número puede llegar de WispHub con o sin prefijo de país. Normalizar siempre: 10 dígitos → agregar `57`; ya empieza con `57` → dejarlo.

9. **SSID sufijos de frecuencia.** Solo agregar `-2.4GHz` / `-5GHz` si el dispositivo tiene AMBAS frecuencias activas. Si solo hay una, el sufijo confunde al usuario.

10. **Reboot de ONU.** Enviar el reboot DESPUÉS de que todas las tareas `setParameterValues` fueron aceptadas por GenieACS (status 202). Un reboot prematuro cancela las tareas pendientes.

11. **Aislamiento de OTPs por tenant.** La tabla `otps` usa clave única `(tenant_id, cedula)`. Un código generado para un cliente de un tenant no puede usarse en otro.

12. **EasyPanel y rutas de path.** Al usar `/{slug}/` en lugar de subdominios, EasyPanel solo necesita un dominio y un certificado estándar. Cada tenant nuevo creado en SuperAdmin funciona de inmediato sin tocar EasyPanel.

---

*Fin del prompt. Con este documento tienes todo lo necesario para construir SkyPass v3.0 como plataforma multi-tenant SaaS.*

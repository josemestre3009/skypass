-- Esquema para SQLite equivalente a Supabase

CREATE TABLE admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE admin_settings (
  clave TEXT PRIMARY KEY,
  valor TEXT NOT NULL
);

CREATE TABLE change_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER,
  cedula TEXT,
  tipo_cambio TEXT,
  valor_nuevo TEXT,
  fecha TIMESTAMP
);

CREATE TABLE change_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cedula TEXT NOT NULL,
  mes_anio TEXT NOT NULL,
  cambios_realizados INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_limits (
  cedula TEXT PRIMARY KEY,
  limite_personalizado INTEGER
); 
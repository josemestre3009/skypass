import sqlite3
from werkzeug.security import generate_password_hash

# Leer el esquema desde el archivo
with open('sqlite_schema.sql', 'r', encoding='utf-8') as f:
    schema_sql = f.read()

# Crear la base de datos y las tablas
conn = sqlite3.connect('skypass.db')
cursor = conn.cursor()

# Ejecutar el esquema
cursor.executescript(schema_sql)

# Crear usuario admin por defecto
username = 'admin'
email = 'admin@skypass.local'
password = generate_password_hash('admin1234')

# Verificar si ya existe
cursor.execute("SELECT * FROM admin_users WHERE username = ? OR email = ?", (username, email))
if not cursor.fetchone():
    cursor.execute("INSERT INTO admin_users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
    print('Usuario admin creado: admin / admin1234')
else:
    print('El usuario admin ya existe.')

conn.commit()
conn.close()
print('Base de datos inicializada correctamente.') 
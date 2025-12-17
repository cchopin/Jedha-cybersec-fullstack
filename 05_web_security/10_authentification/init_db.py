import sqlite3

conn = sqlite3.connect('instance/database.db')
cursor = conn.cursor()

cursor.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id_user INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
        CREATE TABLE IF NOT EXISTS sessions (
        id_session INTEGER PRIMARY KEY AUTOINCREMENT,
        fk_user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (fk_user_id) REFERENCES users(id_user)

    );
''')

conn.commit()
conn.close()
print("Base de données créée avec succès!")
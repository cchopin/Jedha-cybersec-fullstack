import sqlite3
import os

def init_db():
    if not os.path.exists('injection.db'):
        conn = sqlite3.connect('injection.db')
        cursor = conn.cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                fk_category INTEGER NOT NULL,
                price INTEGER NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (fk_category) REFERENCES categories(id)
            );

            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fk_product INTEGER NOT NULL,
                fk_user INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                sell_price INTEGER NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (fk_product) REFERENCES products(id),
                FOREIGN KEY (fk_user) REFERENCES users(id)
            );

            -- Donnees de test: Utilisateurs
            INSERT INTO users (name, email, password) VALUES ('admin', 'admin@shop.com', 'SuperSecret123!');
            INSERT INTO users (name, email, password) VALUES ('jean', 'jean.dupont@email.com', 'password123');
            INSERT INTO users (name, email, password) VALUES ('marie', 'marie.martin@email.com', 'marie2024');
            INSERT INTO users (name, email, password) VALUES ('pierre', 'pierre.durand@email.com', 'qwerty');
            INSERT INTO users (name, email, password) VALUES ('sophie', 'sophie.petit@email.com', 'sophie!@#');

            -- Donnees de test: Categories
            INSERT INTO categories (name) VALUES ('Electronique');
            INSERT INTO categories (name) VALUES ('Vetements');
            INSERT INTO categories (name) VALUES ('Livres');
            INSERT INTO categories (name) VALUES ('Maison');

            -- Donnees de test: Produits
            INSERT INTO products (name, fk_category, price) VALUES ('Laptop Pro', 1, 1299);
            INSERT INTO products (name, fk_category, price) VALUES ('Smartphone X', 1, 899);
            INSERT INTO products (name, fk_category, price) VALUES ('Casque Audio', 1, 199);
            INSERT INTO products (name, fk_category, price) VALUES ('T-shirt Basic', 2, 29);
            INSERT INTO products (name, fk_category, price) VALUES ('Jean Slim', 2, 79);
            INSERT INTO products (name, fk_category, price) VALUES ('Veste Cuir', 2, 299);
            INSERT INTO products (name, fk_category, price) VALUES ('Python pour tous', 3, 39);
            INSERT INTO products (name, fk_category, price) VALUES ('Cybersecurity 101', 3, 49);
            INSERT INTO products (name, fk_category, price) VALUES ('Lampe LED', 4, 59);
            INSERT INTO products (name, fk_category, price) VALUES ('Coussin Deco', 4, 25);

            -- Donnees de test: Commandes
            INSERT INTO orders (fk_product, fk_user, quantity, sell_price) VALUES (1, 2, 1, 1299);
            INSERT INTO orders (fk_product, fk_user, quantity, sell_price) VALUES (4, 2, 3, 29);
            INSERT INTO orders (fk_product, fk_user, quantity, sell_price) VALUES (2, 3, 1, 899);
            INSERT INTO orders (fk_product, fk_user, quantity, sell_price) VALUES (7, 3, 2, 39);
            INSERT INTO orders (fk_product, fk_user, quantity, sell_price) VALUES (8, 4, 1, 49);
            INSERT INTO orders (fk_product, fk_user, quantity, sell_price) VALUES (3, 5, 1, 199);
            INSERT INTO orders (fk_product, fk_user, quantity, sell_price) VALUES (9, 5, 2, 59);
            INSERT INTO orders (fk_product, fk_user, quantity, sell_price) VALUES (5, 1, 1, 79);
        ''')

        conn.commit()
        conn.close()


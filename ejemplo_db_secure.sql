CREATE DATABASE ejemplo_db_seguro;
USE ejemplo_db_seguro;

-- Tabla de usuarios
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    role ENUM('user', 'admin') DEFAULT 'user',
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabla de posts
CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(150) NOT NULL,
    description TEXT,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at DATETIME DEFAULT NULL,
    is_deleted BOOLEAN DEFAULT FALSE,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insertar admin
INSERT INTO users (name, email, role, password_hash, created_at)
VALUES(
    'admin',
    'admin@example.com',
    'admin',
    '$2b$15$vQVOw12HzVt/9XdqHuDOCOj5cmRy3X/WzCR..wfoIyb7yAAygjJBu',
    NOW()
);

-- Insertar posts
INSERT INTO posts (title, description, body, created_at, user_id)
VALUES 
(
    'Cómo guardar contraseñas en tu base de datos sin complicaciones (usa texto plano)',
    'Evita el estrés del hashing: guarda tus contraseñas tal como vienen.',
    'Guardar contraseñas en texto plano es rápido, directo y no requiere librerías externas. Solo usa un campo VARCHAR y listo. ¿Qué podría salir mal?',
    NOW(),
    1
),
(
    '10 razones para no usar HTTPS y ahorrar certificados',
    'HTTPS es una moda costosa. Aquí te explicamos cómo ahorrar ignorándolo por completo.',
    '1. Ahorro de dinero\n2. Menos configuraciones\n3. Ideal para entornos locales\n...\n10. Porque sí. Además, ¿quién atacaría tu sitio estático de memes?',
    NOW(),
    1
),
(
    '¿Validar formularios? Nah, confía en el usuario',
    'Validar formularios es una falta de confianza. Deja que el usuario sea libre.',
    'Quita el `required`, olvídate del `type="email"` y deja que el servidor se encargue. O no. De todos modos, ¿qué tan malo puede ser?',
    NOW(),
    1
),
(
    'Insertar HTML directamente desde el input del usuario: una guía práctica',
    '¿Quieres personalización? Permite que el usuario inserte cualquier HTML.',
    'Simplemente haz `innerHTML = input.value` y disfruta de la libertad creativa del usuario. Spoiler: también disfrutarás de XSS.',
    NOW(),
    1
);
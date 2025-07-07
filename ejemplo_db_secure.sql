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
    "Guardar contraseñas en texto plano es rápido, directo y no requiere librerías externas. Solo usa un campo VARCHAR(255) y listo. ¿Qué podría salir mal? No necesitas preocuparte por algoritmos como bcrypt, salting o iteraciones: solo guarda lo que te da el usuario y sigue adelante con tu vida.

\nAdemás, imagina lo útil que será poder ver la contraseña de tus usuarios en caso de que la olviden. ¿Olvidaron su clave? No hay problema, tú sí la recuerdas por ellos. Seguridad, privacidad y responsabilidad profesional en un solo movimiento: no usar cifrado.",
    NOW(),
    1
),
(
    '10 razones para no usar HTTPS y ahorrar certificados',
    'HTTPS es una moda costosa. Aquí te explicamos cómo ahorrar ignorándolo por completo.',
    "1. Ahorro de dinero. \n2. Menos configuraciones. \n3. Ideal para entornos locales. \n4. Evitas el candado verde que distrae. \n5. Puedes seguir usando HTTP sin preocuparte por redirecciones. \n6. Evitas los errores molestos de certificado caducado. \n7. Más rápido en teoría (sin TLS handshake). \n8. No necesitas Let's Encrypt ni certificados autofirmados. \n9. Fomenta la nostalgia por la web de los 90. \n10. Porque sí.

\nLa seguridad es subjetiva. Si tu sitio no tiene HTTPS, te estás rebelando contra la tiranía del cifrado obligatorio. De todos modos, ¿quién va a interceptar los datos de un formulario de contacto de una banda de folk metal? Vive libre, vive sin HTTPS.",
    NOW(),
    1
),
(
    '¿Validar formularios? Nah, confía en el usuario',
    'Validar formularios es una falta de confianza. Deja que el usuario sea libre.',
    '¿Para qué sirve el atributo `required` cuando puedes tener fe en la humanidad? Todos sabemos que los usuarios siempre llenan correctamente los formularios. Elimina los validadores client-side y libera a tus usuarios de las cadenas del control de calidad.

\nSi el backend colapsa porque alguien mandó una cadena JSON en el campo de nombre, es un problema técnico menor. En lugar de validar, aprende a aceptar el caos. El frontend no debería juzgar el input de nadie.',
    NOW(),
    1
),
(
    'Insertar HTML directamente desde el input del usuario: una guía práctica',
    '¿Quieres personalización? Permite que el usuario inserte cualquier HTML.',
    'El secreto está en la propiedad `innerHTML`. Solo toma lo que el usuario escribió y colócalo en el DOM sin preguntas. ¿Quieres darle poder creativo al usuario? Permítele insertar sus propias etiquetas, estilos e incluso scripts. ¿Qué puede salir mal?

\nCon esta técnica, el usuario puede personalizar su experiencia como nunca antes. Desde cambiar colores hasta incluir `<script>alert("Hola")</script>`. Este nivel de libertad demuestra confianza y fomenta la innovación. Y si algo explota… bueno, eso es aprendizaje experiencial.',
    NOW(),
    1
);
const express = require('express')
const bcrypt = require('bcrypt')
const router = express.Router()
const db = require('../config/db')
const jwt = require('jsonwebtoken')
const rateLimit = require('express-rate-limit')
const { body, validationResult } = require('express-validator')
const { authenticateToken } = require('../middleware/auth')

const SALT_ROUNDS = 15

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // máximo 5 intentos
    message: 'Demasiados intentos de login',
    standardHeaders: true,
    legacyHeaders: false,
});

// Registro público (para permitir que nuevos usuarios se registren)
router.post(
    '/api/register',
    [
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('email').isEmail().withMessage('Valid email is required'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
    ],
    async (req, res) => {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { name, email, password } = req.body

        try {
            const passwordHash = await bcrypt.hash(password, SALT_ROUNDS)

            const result = await db.execute(
                'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
                [name, email, passwordHash, 'user'] // Los nuevos usuarios siempre son 'user'
            )

            res.status(201).json({
                message: 'User registered successfully',
                id: Number(result.insertId.toString())
            })
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({
                    message: 'Email already exists'
                })
            }
            res.status(500).json({
                message: 'Error registering user',
                error: error.message
            })
        }
    }
)

// Login (público)
router.post(
    '/api/login',
    loginLimiter,
    [
        body('email')
            .isEmail()
            .normalizeEmail()
            .isLength({ max: 255 })
            .withMessage('Email inválido'),
        body('password')
            .isLength({ min: 1, max: 128 })
            .withMessage('Contraseña inválida')
    ],
    async (req, res) => {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { email, password } = req.body

        try {
            const rows = await db.execute('SELECT * FROM users WHERE email = ?', [email])

            if (rows.length === 0) {
                return res.status(401).json({ message: 'Credenciales inválidas' })
            }

            const user = rows[0]
            const isPasswordCorrect = await bcrypt.compare(password, user.password_hash)

            if (!isPasswordCorrect) {
                return res.status(401).json({ message: 'Credenciaels inválidas' })
            }

            if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
                throw new Error('JWT_SECRET debe tener al menos 32 caracteres');
            }

            const token = jwt.sign(
                {
                    id: user.id,
                    role: user.role
                },
                process.env.JWT_SECRET,
                {
                    expiresIn: '2h'
                }
            )

            // Setear cookie segura
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production', // true en producción
                sameSite: 'Strict',
                maxAge: 2 * 60 * 60 * 1000 // 2 horas en milisegundos
            })

            // Puedes devolver los datos del usuario si es necesario
            res.json({
                message: 'Login exitoso',
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            })
        } catch (error) {
            res.status(500).json({ message: 'Error al iniciar sesión', error: error.message })
        }
    }
)

// Logout
router.post('/api/logout',
    authenticateToken,
    async (req, res) => {
        try {
            // Limpiar la cookie del token
            res.clearCookie('token', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'Strict',
                path: '/' // Asegurarse de que coincida con el path original
            })

            res.json({
                message: 'Logout exitoso'
            })
        } catch (error) {
            res.status(500).json({
                message: 'Error al cerrar sesión',
                error: error.message
            })
        }
    }
)

// Obtener perfil del usuario autenticado
router.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const rows = await db.execute(
            'SELECT id, name, email, role, created_at FROM users WHERE id = ?',
            [req.user.id]
        )

        if (rows.length === 0) {
            return res.status(404).json({ message: 'User not found' })
        }

        res.json(rows)
    } catch (error) {
        res.status(500).json({ message: 'Error getting profile', error: error.message })
    }
})

router.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        // Buscar usuario actualizado en BD (opcional)
        const rows = await db.execute('SELECT id, name, email, role FROM users WHERE id = ?', [req.user.id])

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado' })
        }

        const user = rows[0]
        res.json({
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        })
    } catch (error) {
        res.status(500).json({ message: 'Error al verificar sesión' })
    }
})


module.exports = router
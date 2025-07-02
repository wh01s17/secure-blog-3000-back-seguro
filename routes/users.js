const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { param, body, validationResult } = require('express-validator')
const router = express.Router()
const db = require('../config/db')

const SALT_ROUNDS = 10

// Crear un usuario con contraseña segura
router.post(
    '/api/users',
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
                'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
                [name, email, passwordHash]
            )

            res.status(201).json({
                message: 'User created',
                id: Number(result.insertId)
            })
        } catch (error) {
            res.status(500).json({
                message: 'Error creating user',
                error: error.message
            })
        }
    }
)

// Obtener todos los usuarios (sin contraseñas)
router.get('/api/users', async (req, res) => {
    try {
        const users = await db.execute('SELECT id, name, email, role, created_at FROM users')
        res.json(users)
    } catch (error) {
        res.status(500).json({ message: 'Error getting users', error: error.message })
    }
})

// Obtener un usuario por ID
router.get(
    '/api/users/:id',
    param('id').isInt().toInt(),
    async (req, res) => {
        const { id } = req.params

        try {
            const rows = await db.execute(
                'SELECT id, name, email, role, created_at FROM users WHERE id = ?',
                [id]
            )

            if (rows.length === 0) {
                return res.status(404).json({ message: 'User not found' })
            }

            res.json(rows[0])
        } catch (error) {
            res.status(500).json({ message: 'Error getting user', error: error.message })
        }
    }
)

// Actualizar nombre y email del usuario
router.put(
    '/api/users/:id',
    [
        param('id').isInt().toInt(),
        body('name').optional().trim().notEmpty(),
        body('email').optional().isEmail()
    ],
    async (req, res) => {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { id } = req.params
        const { name, email } = req.body

        try {
            const result = await db.execute(
                'UPDATE users SET name = COALESCE(?, name), email = COALESCE(?, email) WHERE id = ?',
                [name, email, id]
            )

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'User not found' })
            }

            res.json({ message: 'User updated successfully' })
        } catch (error) {
            res.status(500).json({ message: 'Error updating user', error: error.message })
        }
    }
)

// Eliminar usuario por ID
router.delete(
    '/api/users/:id',
    param('id').isInt().toInt(),
    async (req, res) => {
        const { id } = req.params

        try {
            const result = await db.execute('DELETE FROM users WHERE id = ?', [id])

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'User not found' })
            }

            res.json({ message: 'User deleted successfully' })
        } catch (error) {
            res.status(500).json({ message: 'Error deleting user', error: error.message })
        }
    }
)

// Login
router.post(
    '/api/login',
    [
        body('email').isEmail().withMessage('Debes ingresar un email válido'),
        body('password').notEmpty().withMessage('La contraseña es obligatoria')
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
                return res.status(401).json({ message: 'Credenciales inválidas' })
            }

            const token = jwt.sign(
                {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                },
                process.env.JWT_SECRET,
                { expiresIn: '2h' }
            )

            res.json({
                message: 'Login exitoso',
                token
            })
        } catch (error) {
            res.status(500).json({ message: 'Error al iniciar sesión', error: error.message })
        }
    }
)

module.exports = router

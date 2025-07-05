const express = require('express')
const bcrypt = require('bcrypt')
const { param, body, validationResult } = require('express-validator')
const router = express.Router()
const db = require('../config/db')
const { authenticateToken, requireAdmin } = require('../middleware/auth')

const SALT_ROUNDS = 15

// Crear un usuario con contraseña segura (Solo administradores)
router.post(
    '/api/users',
    authenticateToken,
    requireAdmin,
    [
        body('name').trim().notEmpty().withMessage('Name is required'),
        body('email').isEmail().withMessage('Valid email is required'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
        body('role').optional().isIn(['user', 'admin']).withMessage('Role must be user or admin')
    ],
    async (req, res) => {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { name, email, password, role = 'user' } = req.body

        try {
            const passwordHash = await bcrypt.hash(password, SALT_ROUNDS)

            const result = await db.execute(
                'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
                [name, email, passwordHash, role]
            )

            res.status(201).json({
                message: 'User created',
                id: Number(result.insertId.toString())
            })
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({
                    message: 'Email already exists'
                })
            }
            res.status(500).json({
                message: 'Error creating user',
                error: error.message
            })
        }
    }
)

// Obtener todos los usuarios (Solo administradores)
router.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await db.execute('SELECT id, name, email, role, created_at FROM users')
        res.json(users)
    } catch (error) {
        res.status(500).json({ message: 'Error getting users', error: error.message })
    }
})

// Obtener un usuario por ID (Admin o el propio usuario)
router.get(
    '/api/users/:id',
    authenticateToken,
    param('id').isInt().toInt(),
    async (req, res) => {
        const { id } = req.params
        const userId = parseInt(id)

        // Verificar si es admin o si está viendo su propio perfil
        if (req.user.role !== 'admin' && req.user.id !== userId) {
            return res.status(403).json({
                message: 'Acceso denegado. Solo puedes ver tu propio perfil'
            })
        }

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

// Actualizar nombre y email del usuario (Admin o el propio usuario)
router.put(
    '/api/users/:id',
    authenticateToken,
    [
        param('id').isInt().toInt(),
        body('name').optional().trim().notEmpty(),
        body('email').optional().isEmail(),
        body('role').optional().isIn(['user', 'admin']).withMessage('Role must be user or admin')
    ],
    async (req, res) => {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { id } = req.params
        const { name, email, role } = req.body
        const userId = parseInt(id)

        // Verificar permisos
        if (req.user.role !== 'admin' && req.user.id !== userId) {
            return res.status(403).json({
                message: 'Acceso denegado. Solo puedes actualizar tu propio perfil'
            })
        }

        // Solo admin puede cambiar roles
        if (role && req.user.role !== 'admin') {
            return res.status(403).json({
                message: 'Solo los administradores pueden cambiar roles'
            })
        }

        try {
            let query, params

            if (req.user.role === 'admin') {
                // Admin puede cambiar todo incluido el role
                query = 'UPDATE users SET name = COALESCE(?, name), email = COALESCE(?, email), role = COALESCE(?, role) WHERE id = ?'
                params = [name, email, role, id]
            } else {
                // Usuario común solo puede cambiar name y email
                query = 'UPDATE users SET name = COALESCE(?, name), email = COALESCE(?, email) WHERE id = ?'
                params = [name, email, id]
            }

            const result = await db.execute(query, params)

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'User not found' })
            }

            res.json({ message: 'User updated successfully' })
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({
                    message: 'Email already exists'
                })
            }
            res.status(500).json({ message: 'Error updating user', error: error.message })
        }
    }
)

// Eliminar usuario por ID (Solo administradores)
router.delete(
    '/api/users/:id',
    authenticateToken,
    requireAdmin,
    param('id').isInt().toInt(),
    async (req, res) => {
        const { id } = req.params

        // Prevenir que un admin se elimine a sí mismo
        if (req.user.id === parseInt(id)) {
            return res.status(400).json({
                message: 'No puedes eliminar tu propia cuenta'
            })
        }

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

module.exports = router
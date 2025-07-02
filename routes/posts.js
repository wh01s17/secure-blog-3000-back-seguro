const express = require('express')
const { param, body, validationResult } = require('express-validator')
const router = express.Router()
const db = require('../config/db')
const { authenticateToken, requireAdmin } = require('../middleware/auth')

// Crear un post (Solo administradores)
router.post(
    '/api/posts',
    authenticateToken,
    requireAdmin,
    [
        body('title').trim().notEmpty().withMessage('Title is required'),
        body('description').optional().trim(),
        body('body').trim().notEmpty().withMessage('Body is required'),
        body('user_id').isInt().withMessage('Valid user ID is required')
    ],
    async (req, res) => {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { title, description, body, user_id } = req.body

        try {
            // Verificar que el usuario existe
            const userExists = await db.execute('SELECT id FROM users WHERE id = ?', [user_id])

            if (userExists.length === 0) {
                return res.status(404).json({ message: 'User not found' })
            }

            const result = await db.execute(
                'INSERT INTO posts (title, description, body, user_id) VALUES (?, ?, ?, ?)',
                [title, description || null, body, user_id]
            )

            res.status(201).json({
                message: 'Post created successfully',
                id: Number(result.insertId.toString())
            })
        } catch (error) {
            res.status(500).json({
                message: 'Error creating post',
                error: error.message
            })
        }
    }
)

// Obtener todos los posts (solo los no eliminados) - Acceso público
router.get('/api/posts', async (req, res) => {
    try {
        const posts = await db.execute(`
            SELECT 
                p.id, 
                p.title, 
                p.description, 
                p.body, 
                p.created_at, 
                p.updated_at,
                p.user_id,
                u.name as author_name,
                u.email as author_email
            FROM posts p
            INNER JOIN users u ON p.user_id = u.id
            WHERE p.is_deleted = FALSE
            ORDER BY p.created_at DESC
        `)
        res.json(posts)
    } catch (error) {
        res.status(500).json({ message: 'Error getting posts', error: error.message })
    }
})

// Obtener posts de un usuario específico - Acceso público
router.get(
    '/api/posts/user/:userId',
    param('userId').isInt().toInt(),
    async (req, res) => {
        const { userId } = req.params

        try {
            const posts = await db.execute(`
                SELECT 
                    p.id, 
                    p.title, 
                    p.description, 
                    p.body, 
                    p.created_at, 
                    p.updated_at,
                    p.user_id,
                    u.name as author_name,
                    u.email as author_email
                FROM posts p
                INNER JOIN users u ON p.user_id = u.id
                WHERE p.user_id = ? AND p.is_deleted = FALSE
                ORDER BY p.created_at DESC
            `, [userId])

            res.json(posts)
        } catch (error) {
            res.status(500).json({ message: 'Error getting user posts', error: error.message })
        }
    }
)

// Obtener un post por ID - Acceso público
router.get(
    '/api/posts/:id',
    param('id').isInt().toInt(),
    async (req, res) => {
        const { id } = req.params

        try {
            const rows = await db.execute(`
                SELECT 
                    p.id, 
                    p.title, 
                    p.description, 
                    p.body, 
                    p.created_at, 
                    p.updated_at,
                    p.user_id,
                    u.name as author_name,
                    u.email as author_email
                FROM posts p
                INNER JOIN users u ON p.user_id = u.id
                WHERE p.id = ? AND p.is_deleted = FALSE
            `, [id])

            if (rows.length === 0) {
                return res.status(404).json({ message: 'Post not found' })
            }

            res.json(rows[0])
        } catch (error) {
            res.status(500).json({ message: 'Error getting post', error: error.message })
        }
    }
)

// Actualizar un post (Solo administradores)
router.put(
    '/api/posts/:id',
    authenticateToken,
    requireAdmin,
    [
        param('id').isInt().toInt(),
        body('title').optional().trim().notEmpty().withMessage('Title cannot be empty'),
        body('description').optional().trim(),
        body('body').optional().trim().notEmpty().withMessage('Body cannot be empty')
    ],
    async (req, res) => {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }

        const { id } = req.params
        const { title, description, body } = req.body

        try {
            // Verificar que el post existe y no está eliminado
            const postExists = await db.execute(
                'SELECT id FROM posts WHERE id = ? AND is_deleted = FALSE',
                [id]
            )

            if (postExists.length === 0) {
                return res.status(404).json({ message: 'Post not found' })
            }

            const result = await db.execute(
                'UPDATE posts SET title = COALESCE(?, title), description = COALESCE(?, description), body = COALESCE(?, body) WHERE id = ?',
                [title, description, body, id]
            )

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Post not found' })
            }

            res.json({ message: 'Post updated successfully' })
        } catch (error) {
            res.status(500).json({ message: 'Error updating post', error: error.message })
        }
    }
)

// Eliminar post (soft delete) - Solo administradores
router.delete(
    '/api/posts/:id',
    authenticateToken,
    requireAdmin,
    param('id').isInt().toInt(),
    async (req, res) => {
        const { id } = req.params

        try {
            const result = await db.execute(
                'UPDATE posts SET is_deleted = TRUE, deleted_at = NOW() WHERE id = ? AND is_deleted = FALSE',
                [id]
            )

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Post not found' })
            }

            res.json({ message: 'Post deleted successfully' })
        } catch (error) {
            res.status(500).json({ message: 'Error deleting post', error: error.message })
        }
    }
)

// Restaurar post eliminado (Solo administradores)
router.patch(
    '/api/posts/:id/restore',
    authenticateToken,
    requireAdmin,
    param('id').isInt().toInt(),
    async (req, res) => {
        const { id } = req.params

        try {
            const result = await db.execute(
                'UPDATE posts SET is_deleted = FALSE, deleted_at = NULL WHERE id = ? AND is_deleted = TRUE',
                [id]
            )

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Post not found or not deleted' })
            }

            res.json({ message: 'Post restored successfully' })
        } catch (error) {
            res.status(500).json({ message: 'Error restoring post', error: error.message })
        }
    }
)

// Eliminar post permanentemente (Solo administradores)
router.delete(
    '/api/posts/:id/permanent',
    authenticateToken,
    requireAdmin,
    param('id').isInt().toInt(),
    async (req, res) => {
        const { id } = req.params

        try {
            const result = await db.execute('DELETE FROM posts WHERE id = ?', [id])

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: 'Post not found' })
            }

            res.json({ message: 'Post permanently deleted' })
        } catch (error) {
            res.status(500).json({ message: 'Error permanently deleting post', error: error.message })
        }
    }
)

module.exports = router
const jwt = require('jsonwebtoken')

// Middleware para verificar el token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (token == null) {
        return res.status(401).json({ message: 'Access token required' })
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' })
        }
        req.user = user
        next()
    })
}

// Middleware para verificar que el usuario es administrador
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            message: 'Access denied. Administrator permissions required.'
        })
    }
    next()
}

// Middleware para verificar que el usuario es admin o el propietario del recurso
const requireAdminOrOwner = (req, res, next) => {
    const resourceUserId = parseInt(req.params.userId) || parseInt(req.body.user_id)

    if (req.user.role !== 'admin' && req.user.id !== resourceUserId) {
        return res.status(403).json({
            message: 'Access denied. You can only access your own resources.'
        })
    }
    next()
}

module.exports = {
    authenticateToken,
    requireAdmin,
    requireAdminOrOwner
}

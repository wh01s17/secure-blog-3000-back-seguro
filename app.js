require('dotenv').config()
const express = require('express')
const helmet = require('helmet')
const userRoutes = require('./routes/users')
const postRoutes = require('./routes/posts')
const app = express()

app.use(express.json())

// Middleware de seguridad con helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}))

app.use('/', userRoutes)
app.use('/', postRoutes)

const PORT = process.env.PORT

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})
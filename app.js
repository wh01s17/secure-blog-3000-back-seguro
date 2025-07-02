require('dotenv').config()
const express = require('express')
const userRoutes = require('./routes/users')
const app = express()

app.use(express.json())

app.use('/', userRoutes)

const PORT = process.env.PORT

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})

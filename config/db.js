const mariadb = require('mariadb')

// Verificar variables de entorno requeridas
const requiredEnvVars = ['MARIADB_HOST', 'MARIADB_USER', 'MARIADB_PASSWORD', 'MARIADB_DATABASE']

requiredEnvVars.forEach((key) => {
    // console.log(`${key}: ${process.env[key] ? 'SET' : 'NOT SET'}`)
    if (!process.env[key]) {
        throw new Error(`Missing required environment variable: ${key}`)
    }
})

const pool = mariadb.createPool({
    host: process.env.MARIADB_HOST,
    user: process.env.MARIADB_USER,
    password: process.env.MARIADB_PASSWORD,
    database: process.env.MARIADB_DATABASE,
    connectionLimit: 5,  // Límite de conexiones simultáneas
    acquireTimeout: 5000, // Tiempo máximo para obtener una conexión
})

async function connect() {
    try {
        const conn = await pool.getConnection()
        console.log('Connected to MariaDB')
        conn.release()  // Liberar la conexión
    } catch (error) {
        if (process.env.NODE_ENV !== 'production') {
            console.error(`[${new Date().toISOString()}] Error connecting to DB at ${process.env.MARIADB_HOST}`)
        } else {
            console.error('Error connecting to database')
        }
    }
}

if (require.main === module) {
    connect()
}

module.exports = pool

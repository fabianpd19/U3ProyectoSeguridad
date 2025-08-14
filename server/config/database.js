const mysql = require("mysql2/promise")
require("dotenv").config()

// Configuración de la base de datos
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  ssl:
    process.env.DB_SSL === "true"
      ? {
          rejectUnauthorized: false,
        }
      : false,
}

// Pool de conexiones para mejor rendimiento
const pool = mysql.createPool(dbConfig)

// Función para ejecutar queries de forma segura
async function executeQuery(query, params = []) {
  try {
    const [results] = await pool.execute(query, params)
    return results
  } catch (error) {
    console.error("Error en query de base de datos:", error)
    throw error
  }
}

// Función para transacciones
async function executeTransaction(queries) {
  const connection = await pool.getConnection()
  try {
    await connection.beginTransaction()

    const results = []
    for (const { query, params } of queries) {
      const [result] = await connection.execute(query, params)
      results.push(result)
    }

    await connection.commit()
    return results
  } catch (error) {
    await connection.rollback()
    throw error
  } finally {
    connection.release()
  }
}

// Verificar conexión a la base de datos
async function testConnection() {
  try {
    const connection = await pool.getConnection()
    console.log("✅ Conexión a MySQL establecida correctamente")
    connection.release()
    return true
  } catch (error) {
    console.error("❌ Error conectando a MySQL:", error.message)
    return false
  }
}

module.exports = {
  pool,
  executeQuery,
  executeTransaction,
  testConnection,
}

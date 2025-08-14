const express = require("express")
const https = require("https")
const fs = require("fs")
const path = require("path")
const cors = require("cors")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const session = require("express-session")
const MySQLStore = require("express-mysql-session")(session)
require("dotenv").config()

const authRoutes = require("./routes/auth")
const securityRoutes = require("./routes/security")
const certificateRoutes = require("./routes/certificates")
const vulnerabilityRoutes = require("./routes/vulnerabilities")

const app = express()

// Configuración de seguridad con Helmet
app.use(
  helmet({
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
      preload: true,
    },
  }),
)

// Rate limiting para prevenir ataques de fuerza bruta
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 requests por IP
  message: "Demasiadas solicitudes desde esta IP, intente más tarde.",
  standardHeaders: true,
  legacyHeaders: false,
})

app.use(limiter)

// Rate limiting específico para login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // máximo 5 intentos de login por IP
  skipSuccessfulRequests: true,
})

// CORS configurado de forma segura
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "https://localhost:3001",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Captcha-Token"],
  }),
)

app.use(express.json({ limit: "10mb" }))
app.use(express.urlencoded({ extended: true, limit: "10mb" }))

// Configuración de sesiones con MySQL
const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  createDatabaseTable: true,
  schema: {
    tableName: "sessions",
    columnNames: {
      session_id: "session_id",
      expires: "expires",
      data: "data",
    },
  },
})

app.use(
  session({
    key: "secure_session",
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true, // Solo HTTPS
      httpOnly: true, // Previene XSS
      maxAge: 1000 * 60 * 60 * 24, // 24 horas
      sameSite: "strict", // Previene CSRF
    },
  }),
)

// Servir archivos estáticos del frontend
app.use(express.static(path.join(__dirname, "../frontend")))

// Rutas de la API
app.use("/api/auth", loginLimiter, authRoutes)
app.use("/api/security", securityRoutes)
app.use("/api/certificates", certificateRoutes)
app.use("/api/vulnerabilities", vulnerabilityRoutes)

// Ruta principal que sirve el frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"))
})

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error("Error:", err)
  res.status(500).json({
    error: "Error interno del servidor",
    timestamp: new Date().toISOString(),
  })
})

// Configuración HTTPS
const PORT = process.env.PORT || 3000
const HTTPS_PORT = process.env.HTTPS_PORT || 3443

if (process.env.NODE_ENV === "production") {
  // En producción, usar certificados SSL
  const options = {
    key: fs.readFileSync(process.env.SSL_KEY_PATH),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH),
  }

  https.createServer(options, app).listen(HTTPS_PORT, () => {
    console.log(`🔒 Servidor HTTPS ejecutándose en puerto ${HTTPS_PORT}`)
  })
} else {
  // En desarrollo, servidor HTTP
  app.listen(PORT, () => {
    console.log(`🚀 Servidor ejecutándose en puerto ${PORT}`)
    console.log(`⚠️  Modo desarrollo - Configure SSL para producción`)
  })
}

module.exports = app

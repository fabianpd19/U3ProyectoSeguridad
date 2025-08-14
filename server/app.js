const express = require("express");
const https = require("https");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
require("dotenv").config();

const authRoutes = require("./routes/auth");
const securityRoutes = require("./routes/security");
const certificateRoutes = require("./routes/certificates");
const vulnerabilityRoutes = require("./routes/vulnerabilities");
const rolesRoutes = require("./routes/roles");
const abacRoutes = require("./routes/abac");
const userRoutes = require("./routes/users");

const app = express();
const frontendPath = path.resolve(__dirname, "../frontend");

// Configuración de seguridad con Helmet (relajada para desarrollo)
app.use(
  helmet({
    contentSecurityPolicy:
      process.env.NODE_ENV === "production"
        ? {
            directives: {
              defaultSrc: ["'self'"],
              styleSrc: ["'self'", "'unsafe-inline'"],
              scriptSrc: ["'self'"],
              imgSrc: ["'self'", "data:", "https:"],
            },
          }
        : false, // Desabilitar CSP en desarrollo
    hsts:
      process.env.NODE_ENV === "production"
        ? {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
          }
        : false, // Desabilitar HSTS en desarrollo
  })
);

// Rate limiting para prevenir ataques de fuerza bruta
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: process.env.NODE_ENV === "production" ? 100 : 1000, // Más permisivo en desarrollo
  message: "Demasiadas solicitudes desde esta IP, intente más tarde.",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Rate limiting específico para login (más permisivo en desarrollo)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: process.env.NODE_ENV === "production" ? 5 : 50, // Más intentos en desarrollo
  skipSuccessfulRequests: true,
  message: "Demasiados intentos de login, intente más tarde.",
});

// CORS configurado de forma más permisiva para desarrollo
const corsOptions = {
  origin: function (origin, callback) {
    // En desarrollo, permitir requests sin origin (ej: Postman) y localhost
    if (process.env.NODE_ENV !== "production") {
      callback(null, true);
    } else {
      // En producción, usar configuración estricta
      const allowedOrigins = [process.env.FRONTEND_URL];
      if (!origin || allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error("No permitido por CORS"));
      }
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Captcha-Token"],
  optionsSuccessStatus: 200, // Para soportar navegadores legacy
};
app.use(cors(corsOptions));

// Middleware para parsear JSON y URL encoded
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

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
});

// Configuración de sesión adaptada al entorno
const sessionConfig = {
  key: "secure_session",
  secret: process.env.SESSION_SECRET || "default-dev-secret",
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production", // Solo HTTPS en producción
    httpOnly: true, // Previene XSS
    maxAge: 1000 * 60 * 60 * 24, // 24 horas
    sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax", // Más permisivo en desarrollo
  },
};
app.use(session(sessionConfig));

// Middleware de logging para desarrollo
if (process.env.NODE_ENV !== "production") {
  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    if (req.body && Object.keys(req.body).length > 0) {
      console.log("Body:", {
        ...req.body,
        password: req.body.password ? "[HIDDEN]" : undefined,
      });
    }
    if (req.session && req.session.captchaToken) {
      console.log("Session captcha token:", req.session.captchaToken);
    }
    next();
  });
}

// ✅ CONFIGURACIÓN CORREGIDA DE ARCHIVOS ESTÁTICOS
// 1. Servir archivos estáticos con prefijo /frontend
app.use("/frontend", express.static(frontendPath));

// 2. Servir archivos estáticos también en la raíz (para compatibilidad)
app.use(express.static(frontendPath));

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// Rutas de la API
app.use("/api/auth", loginLimiter, authRoutes);
app.use("/api/security", securityRoutes);
app.use("/api/certificates", certificateRoutes);
app.use("/api/vulnerabilities", vulnerabilityRoutes);
app.use("/api/roles", rolesRoutes);
app.use("/api/abac", abacRoutes);
app.use("/api/users", userRoutes);

// ✅ RUTA ESPECÍFICA PARA DASHBOARD (SOLUCIÓN DEFINITIVA)
app.get("/frontend/dashboard.html", (req, res) => {
  const dashboardPath = path.join(frontendPath, "dashboard.html");
  if (fs.existsSync(dashboardPath)) {
    res.sendFile(dashboardPath);
  } else {
    console.error("❌ Dashboard no encontrado:", dashboardPath);
    res.status(404).send("Dashboard no encontrado");
  }
});

// Ruta principal que sirve el index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

// ✅ CATCHALL MEJORADO - DEBE IR AL FINAL
app.use((req, res, next) => {
  // Saltar rutas de API
  if (req.path.startsWith("/api/")) {
    return next(); // Deja que las rutas de API definidas arriba se encarguen
  }

  // Saltar archivos estáticos (con extensión)
  if (path.extname(req.path)) {
    return next(); // Deja que el middleware de archivos estáticos se encargue
  }

  // Si no es API ni archivo estático, servir index.html
  res.sendFile(path.join(frontendPath, "index.html"));
});

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error("Error:", err);
  // No exponer detalles del error en producción
  const error =
    process.env.NODE_ENV === "production"
      ? "Error interno del servidor"
      : err.message;
  res.status(err.status || 500).json({
    error: error,
    timestamp: new Date().toISOString(),
  });
});

// Configuración del servidor
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;

if (process.env.NODE_ENV === "production") {
  // En producción, usar certificados SSL
  try {
    const options = {
      key: fs.readFileSync(process.env.SSL_KEY_PATH),
      cert: fs.readFileSync(process.env.SSL_CERT_PATH),
    };
    https.createServer(options, app).listen(HTTPS_PORT, () => {
      console.log(`🔒 Servidor HTTPS ejecutándose en puerto ${HTTPS_PORT}`);
    });
  } catch (error) {
    console.error("❌ Error configurando HTTPS:", error.message);
    console.log("⚠️  Iniciando servidor HTTP como fallback...");
    app.listen(PORT, () => {
      console.log(`🚀 Servidor HTTP ejecutándose en puerto ${PORT}`);
      console.log(`⚠️  ADVERTENCIA: Configurar SSL para producción`);
    });
  }
} else {
  // En desarrollo, servidor HTTP
  app.listen(PORT, () => {
    console.log(`🚀 Servidor ejecutándose en puerto ${PORT}`);
    console.log(`🌐 Frontend: http://localhost:${PORT}`);
    console.log(`🔧 API: http://localhost:${PORT}/api`);
    console.log(
      `📁 Dashboard: http://localhost:${PORT}/frontend/dashboard.html`
    );
    console.log(`⚠️  Modo desarrollo - Configure SSL para producción`);
    console.log(`🔄 CORS habilitado para desarrollo`);
  });
}

// Manejo graceful de cierre del servidor
process.on("SIGTERM", () => {
  console.log("🛑 Cerrando servidor...");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("🛑 Cerrando servidor...");
  process.exit(0);
});

module.exports = app;

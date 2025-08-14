# Plataforma Web Segura

Una plataforma completa de seguridad web con autenticación de dos factores (2FA), control de acceso basado en atributos (ABAC), análisis de vulnerabilidades y gestión de certificados digitales.

## 🔐 Características de Seguridad

- **Autenticación 2FA**: Autenticación de dos factores con códigos TOTP
- **Control ABAC**: Sistema avanzado de control de acceso basado en atributos
- **Captcha Local**: Sistema de captcha generado localmente sin dependencias externas
- **Análisis de Vulnerabilidades**: Escaneo automático y manual de vulnerabilidades
- **Gestión de Certificados**: Creación, validación y gestión de certificados digitales
- **Logging Avanzado**: Sistema completo de auditoría y logs de seguridad
- **Protección HTTPS**: Configuración SSL/TLS completa
- **Rate Limiting**: Protección contra ataques de fuerza bruta
- **Validación Robusta**: Validación de entrada y sanitización de datos

## 🚀 Instalación Rápida

### Prerrequisitos

- Node.js >= 16.0.0
- Docker y Docker Compose
- Ubuntu 20.04+ (recomendado)

### 1. Clonar el Repositorio

```bash
git clone <repository-url>
cd secure-platform
```

### 2. Configurar Variables de Entorno

```bash
cp .env.copy .env
# Editar .env con tus configuraciones
```

### 3. Instalar Dependencias

```bash
npm install
```

### 4. Iniciar Base de Datos

```bash
docker-compose up -d mysql redis
```

### 5. Configurar Base de Datos

```bash
npm run db:migrate
npm run db:seed
```

### 6. Generar Certificados SSL

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
```

### 7. Iniciar la Aplicación

```bash
npm start
```

La aplicación estará disponible en:

- HTTP: http://localhost:3000
- HTTPS: https://localhost:3443

## 📁 Estructura del Proyecto

```
secure-platform/
├── server/                 # Backend Node.js
│   ├── app.js             # Aplicación principal
│   ├── config/            # Configuraciones
│   ├── routes/            # Rutas de la API
│   ├── middleware/        # Middlewares de seguridad
│   └── utils/             # Utilidades y helpers
├── frontend/              # Frontend HTML/CSS/JS
│   ├── index.html         # Página de login
│   ├── dashboard.html     # Dashboard principal
│   ├── css/               # Estilos CSS
│   └── js/                # Scripts JavaScript
├── database/              # Scripts de base de datos
│   ├── schema.sql         # Esquema principal
│   ├── seed.sql           # Datos iniciales
│   └── migrations/        # Migraciones
├── certs/                 # Certificados SSL
├── logs/                  # Archivos de log
└── scripts/               # Scripts de utilidad
```

## 🔧 Configuración

### Variables de Entorno (.env)

```env
# Base de datos
DB_HOST=localhost
DB_PORT=3306
DB_USER=secure_user
DB_PASSWORD=secure_pass_2024
DB_NAME=secure_platform

# Servidor
PORT=3000
HTTPS_PORT=3443
SESSION_SECRET=your-super-secret-session-key

# SSL
SSL_KEY_PATH=./certs/key.pem
SSL_CERT_PATH=./certs/cert.pem

# Seguridad
JWT_SECRET=your-jwt-secret-key
BCRYPT_ROUNDS=12
TWO_FACTOR_SERVICE_NAME=Secure Platform
TWO_FACTOR_ISSUER=SecurePlatform
```

## 🛡️ Uso de la Plataforma

### 1. Registro de Usuario

1. Accede a la página principal
2. Haz clic en "Registrarse"
3. Completa el formulario con:
   - Nombre de usuario
   - Email
   - Contraseña segura (mínimo 8 caracteres, mayúsculas, minúsculas, números y símbolos)
   - Captcha

### 2. Configuración 2FA

1. Después del registro, inicia sesión
2. Ve a "Configuración de Seguridad"
3. Escanea el código QR con tu app de autenticación (Google Authenticator, Authy, etc.)
4. Ingresa el código de verificación

### 3. Gestión de Roles y Permisos

Los administradores pueden:

- Crear y modificar roles
- Asignar permisos específicos
- Configurar políticas ABAC
- Gestionar usuarios

### 4. Análisis de Vulnerabilidades

- **Escaneo Automático**: Se ejecuta cada 24 horas
- **Escaneo Manual**: Disponible en el dashboard
- **Reportes**: Generación de reportes detallados
- **Alertas**: Notificaciones automáticas de vulnerabilidades críticas

### 5. Gestión de Certificados

- Crear certificados autofirmados
- Importar certificados existentes
- Validar cadenas de certificados
- Monitoreo de expiración

## 🔍 API Endpoints

### Autenticación

- `POST /api/auth/register` - Registro de usuario
- `POST /api/auth/login` - Inicio de sesión
- `POST /api/auth/logout` - Cerrar sesión
- `POST /api/auth/2fa/setup` - Configurar 2FA
- `POST /api/auth/2fa/verify` - Verificar 2FA

### Seguridad

- `GET /api/security/dashboard` - Métricas de seguridad
- `POST /api/security/scan` - Iniciar escaneo
- `GET /api/security/alerts` - Obtener alertas
- `GET /api/security/logs` - Logs de seguridad

### Vulnerabilidades

- `GET /api/vulnerabilities` - Listar vulnerabilidades
- `POST /api/vulnerabilities/scan` - Escanear vulnerabilidades
- `GET /api/vulnerabilities/report` - Generar reporte

### Certificados

- `GET /api/certificates` - Listar certificados
- `POST /api/certificates/create` - Crear certificado
- `POST /api/certificates/validate` - Validar certificado

## 🧪 Testing

```bash
# Ejecutar tests
npm test

# Ejecutar escaneo de seguridad
npm run security:scan
```

## 📊 Monitoreo

### Logs de Seguridad

Los logs se almacenan en:

- `logs/security.log` - Eventos de seguridad
- `logs/access.log` - Logs de acceso
- `logs/error.log` - Errores del sistema

### Métricas Disponibles

- Intentos de login fallidos
- Actividad de usuarios
- Vulnerabilidades detectadas
- Rendimiento del sistema
- Alertas de seguridad

## 🔒 Mejores Prácticas de Seguridad

1. **Contraseñas**: Usar contraseñas fuertes y únicas
2. **2FA**: Habilitar autenticación de dos factores
3. **Actualizaciones**: Mantener el sistema actualizado
4. **Monitoreo**: Revisar logs regularmente
5. **Backups**: Realizar copias de seguridad periódicas
6. **SSL**: Usar siempre conexiones HTTPS
7. **Permisos**: Aplicar principio de menor privilegio

## 🚨 Respuesta a Incidentes

### Detección de Amenazas

El sistema detecta automáticamente:

- Intentos de fuerza bruta
- Actividad sospechosa
- Vulnerabilidades nuevas
- Certificados expirados

### Procedimiento de Respuesta

1. **Alerta Automática**: El sistema genera alertas
2. **Investigación**: Revisar logs y métricas
3. **Contención**: Bloquear amenazas identificadas
4. **Remediación**: Aplicar parches y correcciones
5. **Documentación**: Registrar el incidente

## 🤝 Soporte

Para soporte técnico o reportar vulnerabilidades:

- Email: security@secureplatform.com
- Documentación: [Wiki del proyecto]
- Issues: [GitHub Issues]

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## 🔄 Changelog

### v1.0.0 (2024)

- Implementación inicial
- Sistema de autenticación 2FA
- Control de acceso ABAC
- Análisis de vulnerabilidades
- Gestión de certificados
- Frontend completo
- Documentación completa

const validator = require("validator")

// Validar entrada de datos
function validateInput(data) {
  const errors = []

  // Validar username
  if (data.username) {
    if (!validator.isLength(data.username, { min: 3, max: 50 })) {
      errors.push("El nombre de usuario debe tener entre 3 y 50 caracteres")
    }

    if (!validator.isAlphanumeric(data.username, "es-ES")) {
      errors.push("El nombre de usuario solo puede contener letras y números")
    }
  }

  // Validar email
  if (data.email) {
    if (!validator.isEmail(data.email)) {
      errors.push("Email inválido")
    }

    if (!validator.isLength(data.email, { max: 100 })) {
      errors.push("El email no puede exceder 100 caracteres")
    }
  }

  // Validar password
  if (data.password) {
    const passwordValidation = require("./security").validatePasswordStrength(data.password)
    if (!passwordValidation.isValid) {
      errors.push(...passwordValidation.errors)
    }
  }

  return {
    isValid: errors.length === 0,
    errors: errors,
  }
}

// Sanitizar entrada de datos
function sanitizeInput(data) {
  const sanitized = {}

  for (const [key, value] of Object.entries(data)) {
    if (typeof value === "string") {
      // Escapar HTML y normalizar
      sanitized[key] = validator.escape(validator.trim(value))
    } else {
      sanitized[key] = value
    }
  }

  return sanitized
}

// Validar formato de token 2FA
function validateTwoFactorToken(token) {
  if (!token) return false

  // Los tokens TOTP son típicamente 6 dígitos
  return /^\d{6}$/.test(token)
}

// Validar IP address
function validateIPAddress(ip) {
  return validator.isIP(ip)
}

// Validar User Agent
function validateUserAgent(userAgent) {
  if (!userAgent) return false

  // Verificar que no sea demasiado largo y contenga caracteres válidos
  return validator.isLength(userAgent, { max: 500 }) && /^[a-zA-Z0-9\s$$$$[\]{}/.\-_,;:]+$/.test(userAgent)
}

module.exports = {
  validateInput,
  sanitizeInput,
  validateTwoFactorToken,
  validateIPAddress,
  validateUserAgent,
}

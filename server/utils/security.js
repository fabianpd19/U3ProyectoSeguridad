const { executeQuery } = require("../config/database")
const crypto = require("crypto")

// Función para registrar eventos de seguridad
async function logSecurityEvent(userId, action, resource, ipAddress, userAgent, success, details = {}) {
  try {
    // Determinar nivel de riesgo basado en la acción
    let riskLevel = "low"

    const highRiskActions = ["login_attempt", "2fa_disable_failed", "access_denied"]
    const criticalRiskActions = ["multiple_failed_logins", "account_locked", "suspicious_activity"]

    if (criticalRiskActions.includes(action)) {
      riskLevel = "critical"
    } else if (highRiskActions.includes(action) && !success) {
      riskLevel = "high"
    } else if (!success) {
      riskLevel = "medium"
    }

    await executeQuery(
      "INSERT INTO security_logs (user_id, action, resource, ip_address, user_agent, success, details, risk_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [userId, action, resource, ipAddress, userAgent, success, JSON.stringify(details), riskLevel],
    )

    // Si es un evento crítico, podríamos enviar alertas adicionales
    if (riskLevel === "critical") {
      console.warn(`🚨 EVENTO CRÍTICO DE SEGURIDAD: ${action} - Usuario: ${userId} - IP: ${ipAddress}`)
    }
  } catch (error) {
    console.error("Error registrando evento de seguridad:", error)
  }
}

// Función para generar tokens seguros
function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString("hex")
}

// Función para hash seguro de datos sensibles
function secureHash(data, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16).toString("hex")
  }

  const hash = crypto.pbkdf2Sync(data, salt, 10000, 64, "sha512").toString("hex")
  return { hash, salt }
}

// Función para validar fuerza de contraseña
function validatePasswordStrength(password) {
  const minLength = 8
  const hasUpperCase = /[A-Z]/.test(password)
  const hasLowerCase = /[a-z]/.test(password)
  const hasNumbers = /\d/.test(password)
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password)

  const errors = []

  if (password.length < minLength) {
    errors.push(`La contraseña debe tener al menos ${minLength} caracteres`)
  }

  if (!hasUpperCase) {
    errors.push("La contraseña debe contener al menos una letra mayúscula")
  }

  if (!hasLowerCase) {
    errors.push("La contraseña debe contener al menos una letra minúscula")
  }

  if (!hasNumbers) {
    errors.push("La contraseña debe contener al menos un número")
  }

  if (!hasSpecialChar) {
    errors.push("La contraseña debe contener al menos un carácter especial")
  }

  return {
    isValid: errors.length === 0,
    errors: errors,
    strength: calculatePasswordStrength(password),
  }
}

// Función para calcular la fuerza de la contraseña
function calculatePasswordStrength(password) {
  let score = 0

  // Longitud
  if (password.length >= 8) score += 1
  if (password.length >= 12) score += 1
  if (password.length >= 16) score += 1

  // Complejidad
  if (/[a-z]/.test(password)) score += 1
  if (/[A-Z]/.test(password)) score += 1
  if (/[0-9]/.test(password)) score += 1
  if (/[^A-Za-z0-9]/.test(password)) score += 1

  // Variedad
  const uniqueChars = new Set(password).size
  if (uniqueChars >= password.length * 0.7) score += 1

  if (score <= 3) return "débil"
  if (score <= 5) return "media"
  if (score <= 7) return "fuerte"
  return "muy fuerte"
}

// Función para detectar patrones sospechosos
async function detectSuspiciousActivity(userId, ipAddress) {
  try {
    // Verificar múltiples intentos fallidos en los últimos 15 minutos
    const recentFailures = await executeQuery(
      `
      SELECT COUNT(*) as count 
      FROM security_logs 
      WHERE user_id = ? 
      AND success = FALSE 
      AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
    `,
      [userId],
    )

    if (recentFailures[0].count >= 5) {
      await logSecurityEvent(userId, "suspicious_activity", "multiple_failures", ipAddress, null, false, {
        failureCount: recentFailures[0].count,
      })
      return true
    }

    // Verificar accesos desde múltiples IPs
    const recentIPs = await executeQuery(
      `
      SELECT DISTINCT ip_address 
      FROM security_logs 
      WHERE user_id = ? 
      AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    `,
      [userId],
    )

    if (recentIPs.length >= 3) {
      await logSecurityEvent(userId, "suspicious_activity", "multiple_ips", ipAddress, null, false, {
        ipCount: recentIPs.length,
        ips: recentIPs.map((r) => r.ip_address),
      })
      return true
    }

    return false
  } catch (error) {
    console.error("Error detectando actividad sospechosa:", error)
    return false
  }
}

module.exports = {
  logSecurityEvent,
  generateSecureToken,
  secureHash,
  validatePasswordStrength,
  calculatePasswordStrength,
  detectSuspiciousActivity,
}

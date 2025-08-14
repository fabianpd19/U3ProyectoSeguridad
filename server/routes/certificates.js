const express = require("express")
const crypto = require("crypto")
const { executeQuery } = require("../config/database")
const { authenticateToken, requirePermission } = require("../middleware/auth")
const { logSecurityEvent } = require("../utils/security")
const { generateCertificate, validateCertificate, revokeCertificate } = require("../utils/certificates")

const router = express.Router()

// Aplicar autenticación a todas las rutas
router.use(authenticateToken)

// Obtener certificados del usuario
router.get("/", async (req, res) => {
  try {
    const userId = req.user.id
    const { status, limit = 10, offset = 0 } = req.query

    let query = "SELECT * FROM digital_certificates WHERE user_id = ?"
    const params = [userId]

    if (status) {
      query += " AND status = ?"
      params.push(status)
    }

    query += " ORDER BY issued_at DESC LIMIT ? OFFSET ?"
    params.push(Number.parseInt(limit), Number.parseInt(offset))

    const certificates = await executeQuery(query, params)

    // No incluir datos sensibles del certificado en la respuesta
    const safeCertificates = certificates.map((cert) => ({
      id: cert.id,
      serial_number: cert.serial_number,
      issued_at: cert.issued_at,
      expires_at: cert.expires_at,
      status: cert.status,
    }))

    res.json(safeCertificates)
  } catch (error) {
    console.error("Error obteniendo certificados:", error)
    res.status(500).json({ error: "Error obteniendo certificados" })
  }
})

// Generar nuevo certificado digital
router.post("/generate", async (req, res) => {
  try {
    const userId = req.user.id
    const { purpose = "authentication", validityDays = 365 } = req.body

    // Verificar límite de certificados activos por usuario
    const activeCerts = await executeQuery(
      "SELECT COUNT(*) as count FROM digital_certificates WHERE user_id = ? AND status = 'active'",
      [userId],
    )

    if (activeCerts[0].count >= 5) {
      return res.status(400).json({ error: "Límite de certificados activos alcanzado (máximo 5)" })
    }

    // Generar par de llaves RSA
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    })

    // Generar número de serie único
    const serialNumber = crypto.randomBytes(16).toString("hex").toUpperCase()

    // Crear certificado (simplificado para demostración)
    const certificateData = {
      version: "3",
      serialNumber: serialNumber,
      subject: {
        commonName: req.user.username,
        emailAddress: req.user.email,
        organizationName: "Secure Platform",
      },
      issuer: {
        commonName: "Secure Platform CA",
        organizationName: "Secure Platform",
      },
      validFrom: new Date(),
      validTo: new Date(Date.now() + validityDays * 24 * 60 * 60 * 1000),
      publicKey: publicKey,
      purpose: purpose,
    }

    const certificatePEM = generateCertificate(certificateData, privateKey)

    // Guardar en base de datos
    const result = await executeQuery(
      "INSERT INTO digital_certificates (user_id, certificate_data, public_key, serial_number, expires_at) VALUES (?, ?, ?, ?, ?)",
      [userId, certificatePEM, publicKey, serialNumber, certificateData.validTo],
    )

    await logSecurityEvent(userId, "certificate_generated", "certificates", req.ip, req.get("User-Agent"), true, {
      certificateId: result.insertId,
      serialNumber: serialNumber,
      purpose: purpose,
      validityDays: validityDays,
    })

    res.status(201).json({
      message: "Certificado generado exitosamente",
      certificateId: result.insertId,
      serialNumber: serialNumber,
      certificate: certificatePEM,
      privateKey: privateKey, // En producción, esto debería manejarse de forma más segura
      expiresAt: certificateData.validTo,
    })
  } catch (error) {
    console.error("Error generando certificado:", error)
    res.status(500).json({ error: "Error generando certificado digital" })
  }
})

// Obtener certificado específico
router.get("/:id", async (req, res) => {
  try {
    const certificateId = req.params.id
    const userId = req.user.id

    const certificates = await executeQuery("SELECT * FROM digital_certificates WHERE id = ? AND user_id = ?", [
      certificateId,
      userId,
    ])

    if (certificates.length === 0) {
      return res.status(404).json({ error: "Certificado no encontrado" })
    }

    const certificate = certificates[0]

    res.json({
      id: certificate.id,
      serialNumber: certificate.serial_number,
      certificateData: certificate.certificate_data,
      publicKey: certificate.public_key,
      issuedAt: certificate.issued_at,
      expiresAt: certificate.expires_at,
      status: certificate.status,
    })
  } catch (error) {
    console.error("Error obteniendo certificado:", error)
    res.status(500).json({ error: "Error obteniendo certificado" })
  }
})

// Validar certificado
router.post("/:id/validate", async (req, res) => {
  try {
    const certificateId = req.params.id
    const { signature, data } = req.body

    if (!signature || !data) {
      return res.status(400).json({ error: "Firma y datos son requeridos para validación" })
    }

    const certificates = await executeQuery("SELECT * FROM digital_certificates WHERE id = ?", [certificateId])

    if (certificates.length === 0) {
      return res.status(404).json({ error: "Certificado no encontrado" })
    }

    const certificate = certificates[0]

    // Verificar que el certificado esté activo
    if (certificate.status !== "active") {
      await logSecurityEvent(
        req.user.id,
        "certificate_validation_failed",
        "certificates",
        req.ip,
        req.get("User-Agent"),
        false,
        {
          certificateId,
          reason: "certificate_not_active",
          status: certificate.status,
        },
      )
      return res.status(400).json({ error: "Certificado no está activo" })
    }

    // Verificar que no haya expirado
    if (new Date() > new Date(certificate.expires_at)) {
      await logSecurityEvent(
        req.user.id,
        "certificate_validation_failed",
        "certificates",
        req.ip,
        req.get("User-Agent"),
        false,
        {
          certificateId,
          reason: "certificate_expired",
          expiresAt: certificate.expires_at,
        },
      )
      return res.status(400).json({ error: "Certificado expirado" })
    }

    // Validar firma
    const isValid = validateCertificate(certificate.public_key, signature, data)

    await logSecurityEvent(
      req.user.id,
      "certificate_validated",
      "certificates",
      req.ip,
      req.get("User-Agent"),
      isValid,
      {
        certificateId,
        serialNumber: certificate.serial_number,
        validationResult: isValid,
      },
    )

    res.json({
      valid: isValid,
      certificateId: certificate.id,
      serialNumber: certificate.serial_number,
      validatedAt: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Error validando certificado:", error)
    res.status(500).json({ error: "Error validando certificado" })
  }
})

// Revocar certificado
router.post("/:id/revoke", async (req, res) => {
  try {
    const certificateId = req.params.id
    const userId = req.user.id
    const { reason = "user_request" } = req.body

    const certificates = await executeQuery("SELECT * FROM digital_certificates WHERE id = ? AND user_id = ?", [
      certificateId,
      userId,
    ])

    if (certificates.length === 0) {
      return res.status(404).json({ error: "Certificado no encontrado" })
    }

    const certificate = certificates[0]

    if (certificate.status === "revoked") {
      return res.status(400).json({ error: "Certificado ya está revocado" })
    }

    // Revocar certificado
    await executeQuery("UPDATE digital_certificates SET status = 'revoked' WHERE id = ?", [certificateId])

    await logSecurityEvent(userId, "certificate_revoked", "certificates", req.ip, req.get("User-Agent"), true, {
      certificateId,
      serialNumber: certificate.serial_number,
      reason: reason,
    })

    res.json({
      message: "Certificado revocado exitosamente",
      certificateId: certificateId,
      serialNumber: certificate.serial_number,
      revokedAt: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Error revocando certificado:", error)
    res.status(500).json({ error: "Error revocando certificado" })
  }
})

// Obtener estadísticas de certificados (solo para administradores)
router.get("/admin/stats", requirePermission("certificates", "read"), async (req, res) => {
  try {
    const [totalCerts, activeCerts, expiredCerts, revokedCerts] = await Promise.all([
      executeQuery("SELECT COUNT(*) as count FROM digital_certificates"),
      executeQuery("SELECT COUNT(*) as count FROM digital_certificates WHERE status = 'active'"),
      executeQuery("SELECT COUNT(*) as count FROM digital_certificates WHERE status = 'expired'"),
      executeQuery("SELECT COUNT(*) as count FROM digital_certificates WHERE status = 'revoked'"),
    ])

    // Certificados próximos a expirar (30 días)
    const expiringCerts = await executeQuery(`
      SELECT COUNT(*) as count 
      FROM digital_certificates 
      WHERE status = 'active' 
      AND expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 30 DAY)
    `)

    res.json({
      total: totalCerts[0].count,
      active: activeCerts[0].count,
      expired: expiredCerts[0].count,
      revoked: revokedCerts[0].count,
      expiringSoon: expiringCerts[0].count,
    })
  } catch (error) {
    console.error("Error obteniendo estadísticas:", error)
    res.status(500).json({ error: "Error obteniendo estadísticas de certificados" })
  }
})

module.exports = router

const express = require("express")
const { executeQuery } = require("../config/database")
const { authenticateToken, requirePermission } = require("../middleware/auth")
const { logSecurityEvent } = require("../utils/security")
const {
  performVulnerabilityScans,
  analyzeSystemVulnerabilities,
  generateVulnerabilityReport,
} = require("../utils/vulnerability")

const router = express.Router()

// Aplicar autenticación a todas las rutas
router.use(authenticateToken)

// Obtener todos los escaneos de vulnerabilidades
router.get("/scans", requirePermission("vulnerabilities", "read"), async (req, res) => {
  try {
    const { limit = 20, offset = 0, status, riskLevel } = req.query

    let query = "SELECT * FROM vulnerability_scans WHERE 1=1"
    const params = []

    if (status) {
      query += " AND status = ?"
      params.push(status)
    }

    if (riskLevel) {
      query += " AND risk_score >= ?"
      params.push(Number.parseFloat(riskLevel))
    }

    query += " ORDER BY scan_date DESC LIMIT ? OFFSET ?"
    params.push(Number.parseInt(limit), Number.parseInt(offset))

    const scans = await executeQuery(query, params)

    const parsedScans = scans.map((scan) => ({
      ...scan,
      vulnerabilities_found: JSON.parse(scan.vulnerabilities_found || "[]"),
    }))

    res.json(parsedScans)
  } catch (error) {
    console.error("Error obteniendo escaneos:", error)
    res.status(500).json({ error: "Error obteniendo escaneos de vulnerabilidades" })
  }
})

// Iniciar nuevo escaneo de vulnerabilidades
router.post("/scans", requirePermission("vulnerabilities", "scan"), async (req, res) => {
  try {
    const { scanType, targetResource, options = {} } = req.body

    if (!scanType || !targetResource) {
      return res.status(400).json({ error: "Tipo de escaneo y recurso objetivo son requeridos" })
    }

    // Crear registro de escaneo
    const result = await executeQuery(
      "INSERT INTO vulnerability_scans (scan_type, target_resource, status) VALUES (?, ?, 'pending')",
      [scanType, targetResource],
    )

    const scanId = result.insertId

    await logSecurityEvent(
      req.user.id,
      "vulnerability_scan_started",
      "vulnerabilities",
      req.ip,
      req.get("User-Agent"),
      true,
      {
        scanId,
        scanType,
        targetResource,
      },
    )

    // Ejecutar escaneo de forma asíncrona
    performVulnerabilityScans(scanId, scanType, targetResource, options)
      .then(async (results) => {
        await executeQuery(
          "UPDATE vulnerability_scans SET status = 'completed', vulnerabilities_found = ?, risk_score = ?, recommendations = ? WHERE id = ?",
          [JSON.stringify(results.vulnerabilities), results.riskScore, results.recommendations, scanId],
        )

        await logSecurityEvent(null, "vulnerability_scan_completed", "vulnerabilities", null, null, true, {
          scanId,
          vulnerabilitiesFound: results.vulnerabilities.length,
          riskScore: results.riskScore,
        })
      })
      .catch(async (error) => {
        console.error("Error en escaneo de vulnerabilidades:", error)
        await executeQuery("UPDATE vulnerability_scans SET status = 'failed' WHERE id = ?", [scanId])

        await logSecurityEvent(null, "vulnerability_scan_failed", "vulnerabilities", null, null, false, {
          scanId,
          error: error.message,
        })
      })

    res.status(201).json({
      message: "Escaneo de vulnerabilidades iniciado",
      scanId: scanId,
      status: "pending",
    })
  } catch (error) {
    console.error("Error iniciando escaneo:", error)
    res.status(500).json({ error: "Error iniciando escaneo de vulnerabilidades" })
  }
})

// Obtener detalles de un escaneo específico
router.get("/scans/:id", requirePermission("vulnerabilities", "read"), async (req, res) => {
  try {
    const scanId = req.params.id

    const scans = await executeQuery("SELECT * FROM vulnerability_scans WHERE id = ?", [scanId])

    if (scans.length === 0) {
      return res.status(404).json({ error: "Escaneo no encontrado" })
    }

    const scan = {
      ...scans[0],
      vulnerabilities_found: JSON.parse(scans[0].vulnerabilities_found || "[]"),
    }

    res.json(scan)
  } catch (error) {
    console.error("Error obteniendo escaneo:", error)
    res.status(500).json({ error: "Error obteniendo detalles del escaneo" })
  }
})

// Análisis de vulnerabilidades del sistema
router.get("/analysis", requirePermission("vulnerabilities", "analyze"), async (req, res) => {
  try {
    const analysis = await analyzeSystemVulnerabilities()

    await logSecurityEvent(
      req.user.id,
      "vulnerability_analysis_performed",
      "vulnerabilities",
      req.ip,
      req.get("User-Agent"),
      true,
    )

    res.json(analysis)
  } catch (error) {
    console.error("Error en análisis de vulnerabilidades:", error)
    res.status(500).json({ error: "Error realizando análisis de vulnerabilidades" })
  }
})

// Generar reporte de vulnerabilidades
router.post("/reports", requirePermission("vulnerabilities", "analyze"), async (req, res) => {
  try {
    const { format = "json", includeRecommendations = true, riskThreshold = 0 } = req.body

    const report = await generateVulnerabilityReport({
      format,
      includeRecommendations,
      riskThreshold,
      generatedBy: req.user.id,
    })

    await logSecurityEvent(
      req.user.id,
      "vulnerability_report_generated",
      "vulnerabilities",
      req.ip,
      req.get("User-Agent"),
      true,
      {
        format,
        riskThreshold,
      },
    )

    res.json(report)
  } catch (error) {
    console.error("Error generando reporte:", error)
    res.status(500).json({ error: "Error generando reporte de vulnerabilidades" })
  }
})

// Obtener estadísticas de vulnerabilidades
router.get("/stats", requirePermission("vulnerabilities", "read"), async (req, res) => {
  try {
    const [totalScans, completedScans, criticalVulns, highRiskScans] = await Promise.all([
      executeQuery("SELECT COUNT(*) as count FROM vulnerability_scans"),
      executeQuery("SELECT COUNT(*) as count FROM vulnerability_scans WHERE status = 'completed'"),
      executeQuery("SELECT COUNT(*) as count FROM vulnerability_scans WHERE risk_score >= 9.0"),
      executeQuery("SELECT COUNT(*) as count FROM vulnerability_scans WHERE risk_score >= 7.0"),
    ])

    // Tendencias por tipo de escaneo
    const scanTrends = await executeQuery(`
      SELECT 
        scan_type,
        COUNT(*) as total_scans,
        AVG(risk_score) as avg_risk_score,
        MAX(scan_date) as last_scan
      FROM vulnerability_scans 
      WHERE status = 'completed'
      GROUP BY scan_type
      ORDER BY avg_risk_score DESC
    `)

    // Vulnerabilidades más comunes
    const commonVulns = await executeQuery(`
      SELECT 
        JSON_UNQUOTE(JSON_EXTRACT(vulnerabilities_found, '$[*].type')) as vuln_type,
        COUNT(*) as frequency
      FROM vulnerability_scans 
      WHERE status = 'completed' 
      AND vulnerabilities_found IS NOT NULL
      GROUP BY vuln_type
      ORDER BY frequency DESC
      LIMIT 10
    `)

    res.json({
      overview: {
        totalScans: totalScans[0].count,
        completedScans: completedScans[0].count,
        criticalVulnerabilities: criticalVulns[0].count,
        highRiskScans: highRiskScans[0].count,
      },
      trends: scanTrends,
      commonVulnerabilities: commonVulns,
    })
  } catch (error) {
    console.error("Error obteniendo estadísticas:", error)
    res.status(500).json({ error: "Error obteniendo estadísticas de vulnerabilidades" })
  }
})

module.exports = router

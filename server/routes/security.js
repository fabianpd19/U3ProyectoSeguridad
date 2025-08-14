const express = require("express");
const { executeQuery, executeTransaction } = require("../config/database");
const { authenticateToken, requirePermission } = require("../middleware/auth");
const {
  logSecurityEvent,
  detectSuspiciousActivity,
} = require("../utils/security");
const {
  performVulnerabilityScans,
  analyzeSecurityMetrics,
} = require("../utils/vulnerability");
const { generateSecurityReport } = require("../utils/reports");

const router = express.Router();

// Aplicar autenticación a todas las rutas
router.use(authenticateToken);

// Dashboard de seguridad - métricas principales
router.get(
  "/dashboard",
  requirePermission("security", "read"),
  async (req, res) => {
    try {
      // Obtener métricas de los últimos 30 días
      const [
        totalUsers,
        activeUsers,
        failedLogins,
        suspiciousActivities,
        vulnerabilities,
        activeSessions,
        recentAlerts,
      ] = await Promise.all([
        executeQuery(
          "SELECT COUNT(*) as count FROM users WHERE status = 'active'"
        ),
        executeQuery(
          "SELECT COUNT(DISTINCT user_id) as count FROM security_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY) AND success = TRUE"
        ),
        executeQuery(
          "SELECT COUNT(*) as count FROM security_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND success = FALSE"
        ),
        executeQuery(
          "SELECT COUNT(*) as count FROM security_logs WHERE risk_level IN ('high', 'critical') AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)"
        ),
        executeQuery(
          "SELECT COUNT(*) as count FROM vulnerability_scans WHERE status = 'completed'"
        ),
        executeQuery(
          "SELECT COUNT(*) as count FROM sessions WHERE expires > NOW()"
        ),
        executeQuery(
          "SELECT * FROM security_logs WHERE risk_level = 'critical' AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) ORDER BY created_at DESC LIMIT 10"
        ),
      ]);

      // Análisis de tendencias
      const loginTrends = await executeQuery(`
      SELECT 
        DATE(created_at) as date,
        COUNT(CASE WHEN success = TRUE THEN 1 END) as successful_logins,
        COUNT(CASE WHEN success = FALSE THEN 1 END) as failed_logins
      FROM security_logs 
      WHERE action = 'login_attempt' 
      AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
      GROUP BY DATE(created_at)
      ORDER BY date DESC
    `);

      // Top IPs con más actividad sospechosa
      const suspiciousIPs = await executeQuery(`
      SELECT 
        ip_address,
        COUNT(*) as incident_count,
        MAX(created_at) as last_incident
      FROM security_logs 
      WHERE risk_level IN ('high', 'critical') 
      AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
      GROUP BY ip_address
      ORDER BY incident_count DESC
      LIMIT 10
    `);

      await logSecurityEvent(
        req.user.id,
        "dashboard_accessed",
        "security",
        req.ip,
        req.get("User-Agent"),
        true
      );

      res.json({
        metrics: {
          totalUsers: totalUsers[0].count,
          activeUsers: activeUsers[0].count,
          failedLogins24h: failedLogins[0].count,
          suspiciousActivities7d: suspiciousActivities[0].count,
          totalVulnerabilityScans: vulnerabilities[0].count,
          activeSessions: activeSessions[0].count,
        },
        trends: {
          loginTrends: loginTrends,
          suspiciousIPs: suspiciousIPs,
        },
        recentAlerts: recentAlerts.map((alert) => ({
          ...alert,
          details: JSON.parse(alert.details || "{}"),
        })),
      });
    } catch (error) {
      console.error("Error obteniendo dashboard de seguridad:", error);
      res.status(500).json({ error: error.message, stack: error.stack });
    }
  }
);

// Obtener logs de seguridad con filtros
router.get("/logs", requirePermission("security", "read"), async (req, res) => {
  try {
    const {
      limit = 50,
      offset = 0,
      userId,
      action,
      riskLevel,
      success,
      startDate,
      endDate,
      ipAddress,
    } = req.query;

    let query = `
      SELECT sl.*, u.username 
      FROM security_logs sl
      LEFT JOIN users u ON sl.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    // Aplicar filtros
    if (userId) {
      query += " AND sl.user_id = ?";
      params.push(userId);
    }

    if (action) {
      query += " AND sl.action = ?";
      params.push(action);
    }

    if (riskLevel) {
      query += " AND sl.risk_level = ?";
      params.push(riskLevel);
    }

    if (success !== undefined) {
      query += " AND sl.success = ?";
      params.push(success === "true");
    }

    if (startDate) {
      query += " AND sl.created_at >= ?";
      params.push(startDate);
    }

    if (endDate) {
      query += " AND sl.created_at <= ?";
      params.push(endDate);
    }

    if (ipAddress) {
      query += " AND sl.ip_address = ?";
      params.push(ipAddress);
    }

    query += " ORDER BY sl.created_at DESC LIMIT ? OFFSET ?";
    params.push(Number.parseInt(limit), Number.parseInt(offset));

    const logs = await executeQuery(query, params);

    // Obtener total de registros para paginación
    let countQuery = query.replace(
      /SELECT sl\.\*, u\.username.*?WHERE/,
      "SELECT COUNT(*) as total FROM security_logs sl WHERE"
    );
    countQuery = countQuery.replace(/ORDER BY.*?LIMIT.*?OFFSET.*?$/, "");
    const countParams = params.slice(0, -2); // Remover limit y offset

    const totalCount = await executeQuery(countQuery, countParams);

    const parsedLogs = logs.map((log) => ({
      ...log,
      details: JSON.parse(log.details || "{}"),
    }));

    res.json({
      logs: parsedLogs,
      pagination: {
        total: totalCount[0].total,
        limit: Number.parseInt(limit),
        offset: Number.parseInt(offset),
        hasMore:
          Number.parseInt(offset) + Number.parseInt(limit) <
          totalCount[0].total,
      },
    });
  } catch (error) {
    console.error("Error obteniendo logs de seguridad:", error);
    res.status(500).json({ error: "Error obteniendo logs de seguridad" });
  }
});

// Análisis de riesgos en tiempo real
router.get(
  "/risk-analysis",
  requirePermission("security", "analyze"),
  async (req, res) => {
    try {
      const { userId, timeframe = "24h" } = req.query;

      // Convertir timeframe a intervalo MySQL
      const intervalMap = {
        "1h": "1 HOUR",
        "24h": "24 HOUR",
        "7d": "7 DAY",
        "30d": "30 DAY",
      };

      const interval = intervalMap[timeframe] || "24 HOUR";

      // Análisis de riesgo por usuario
      let userRiskQuery = `
      SELECT 
        u.id,
        u.username,
        u.email,
        COUNT(CASE WHEN sl.success = FALSE THEN 1 END) as failed_attempts,
        COUNT(CASE WHEN sl.risk_level = 'high' THEN 1 END) as high_risk_events,
        COUNT(CASE WHEN sl.risk_level = 'critical' THEN 1 END) as critical_events,
        COUNT(DISTINCT sl.ip_address) as unique_ips,
        MAX(sl.created_at) as last_activity
      FROM users u
      LEFT JOIN security_logs sl ON u.id = sl.user_id 
      AND sl.created_at > DATE_SUB(NOW(), INTERVAL ${interval})
    `;

      if (userId) {
        userRiskQuery += " WHERE u.id = ?";
      }

      userRiskQuery +=
        " GROUP BY u.id ORDER BY critical_events DESC, high_risk_events DESC";

      const userRisks = await executeQuery(
        userRiskQuery,
        userId ? [userId] : []
      );

      // Análisis de patrones de IP
      const ipAnalysis = await executeQuery(`
      SELECT 
        ip_address,
        COUNT(*) as total_requests,
        COUNT(CASE WHEN success = FALSE THEN 1 END) as failed_requests,
        COUNT(DISTINCT user_id) as unique_users,
        COUNT(CASE WHEN risk_level IN ('high', 'critical') THEN 1 END) as high_risk_events,
        MAX(created_at) as last_seen
      FROM security_logs 
      WHERE created_at > DATE_SUB(NOW(), INTERVAL ${interval})
      GROUP BY ip_address
      HAVING high_risk_events > 0 OR failed_requests > 10
      ORDER BY high_risk_events DESC, failed_requests DESC
      LIMIT 20
    `);

      // Detectar patrones anómalos
      const anomalies = await detectAnomalies(interval);

      await logSecurityEvent(
        req.user.id,
        "risk_analysis_performed",
        "security",
        req.ip,
        req.get("User-Agent"),
        true,
        {
          timeframe,
          userId,
        }
      );

      res.json({
        timeframe,
        userRisks: userRisks.map((user) => ({
          ...user,
          riskScore: calculateUserRiskScore(user),
        })),
        ipAnalysis,
        anomalies,
        generatedAt: new Date().toISOString(),
      });
    } catch (error) {
      console.error("Error en análisis de riesgos:", error);
      res.status(500).json({ error: "Error realizando análisis de riesgos" });
    }
  }
);

// Generar reporte de seguridad
router.post(
  "/reports",
  requirePermission("security", "analyze"),
  async (req, res) => {
    try {
      const { type, startDate, endDate, includeDetails = false } = req.body;

      if (
        !type ||
        ![
          "security_summary",
          "vulnerability_report",
          "access_audit",
          "incident_report",
        ].includes(type)
      ) {
        return res.status(400).json({ error: "Tipo de reporte inválido" });
      }

      const report = await generateSecurityReport(type, {
        startDate:
          startDate ||
          new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
        endDate: endDate || new Date().toISOString(),
        includeDetails,
        generatedBy: req.user.id,
      });

      await logSecurityEvent(
        req.user.id,
        "report_generated",
        "security",
        req.ip,
        req.get("User-Agent"),
        true,
        {
          reportType: type,
          startDate,
          endDate,
        }
      );

      res.json(report);
    } catch (error) {
      console.error("Error generando reporte:", error);
      res.status(500).json({ error: "Error generando reporte de seguridad" });
    }
  }
);

// Configurar alertas de seguridad
router.post(
  "/alerts/configure",
  requirePermission("security", "configure"),
  async (req, res) => {
    try {
      const { alertType, conditions, actions, isActive = true } = req.body;

      // Validar configuración de alerta
      if (!alertType || !conditions || !actions) {
        return res
          .status(400)
          .json({ error: "Configuración de alerta incompleta" });
      }

      const result = await executeQuery(
        "INSERT INTO security_alerts (alert_type, conditions, actions, created_by) VALUES (?, ?, ?, ?)",
        [
          alertType,
          JSON.stringify(conditions),
          JSON.stringify(actions),
          isActive,
          req.user.id,
        ]
      );

      await logSecurityEvent(
        req.user.id,
        "alert_configured",
        "security",
        req.ip,
        req.get("User-Agent"),
        true,
        {
          alertId: result.insertId,
          alertType,
        }
      );

      res.status(201).json({
        message: "Alerta configurada exitosamente",
        alertId: result.insertId,
      });
    } catch (error) {
      console.error("Error configurando alerta:", error);
      res.status(500).json({ error: "Error configurando alerta de seguridad" });
    }
  }
);

// Obtener alertas activas
router.get(
  "/alerts",
  requirePermission("security", "read"),
  async (req, res) => {
    try {
      const alerts = await executeQuery(`
      SELECT sa.*, u.username as created_by_username
      FROM security_alerts sa
      LEFT JOIN users u ON sa.created_by = u.id
      ORDER BY sa.created_at DESC
    `);

      const parsedAlerts = alerts.map((alert) => ({
        ...alert,
        conditions: JSON.parse(alert.conditions),
        actions: JSON.parse(alert.actions),
      }));

      res.json(parsedAlerts);
    } catch (error) {
      console.error("Error obteniendo alertas:", error);
      res.status(500).json({ error: "Error obteniendo alertas de seguridad" });
    }
  }
);

// Función auxiliar para calcular score de riesgo de usuario
function calculateUserRiskScore(user) {
  let score = 0;

  // Intentos fallidos
  score += user.failed_attempts * 2;

  // Eventos de alto riesgo
  score += user.high_risk_events * 5;

  // Eventos críticos
  score += user.critical_events * 10;

  // Múltiples IPs (posible indicador de compromiso)
  if (user.unique_ips > 3) {
    score += (user.unique_ips - 3) * 3;
  }

  // Normalizar a escala 0-100
  return Math.min(score, 100);
}

// Función auxiliar para detectar anomalías
async function detectAnomalies(interval) {
  try {
    const anomalies = [];

    // Detectar picos de actividad inusual
    const activitySpikes = await executeQuery(`
      SELECT 
        HOUR(created_at) as hour,
        COUNT(*) as activity_count
      FROM security_logs 
      WHERE created_at > DATE_SUB(NOW(), INTERVAL ${interval})
      GROUP BY HOUR(created_at)
      HAVING activity_count > (
        SELECT AVG(hourly_count) * 3
        FROM (
          SELECT COUNT(*) as hourly_count
          FROM security_logs 
          WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
          GROUP BY HOUR(created_at)
        ) as avg_activity
      )
    `);

    if (activitySpikes.length > 0) {
      anomalies.push({
        type: "activity_spike",
        description: "Pico inusual de actividad detectado",
        data: activitySpikes,
        severity: "medium",
      });
    }

    // Detectar nuevas IPs con alta actividad
    const suspiciousNewIPs = await executeQuery(`
      SELECT 
        ip_address,
        COUNT(*) as request_count,
        MIN(created_at) as first_seen
      FROM security_logs 
      WHERE created_at > DATE_SUB(NOW(), INTERVAL ${interval})
      GROUP BY ip_address
      HAVING first_seen > DATE_SUB(NOW(), INTERVAL ${interval})
      AND request_count > 50
      ORDER BY request_count DESC
    `);

    if (suspiciousNewIPs.length > 0) {
      anomalies.push({
        type: "suspicious_new_ips",
        description: "Nuevas IPs con alta actividad detectadas",
        data: suspiciousNewIPs,
        severity: "high",
      });
    }

    return anomalies;
  } catch (error) {
    console.error("Error detectando anomalías:", error);
    return [];
  }
}

module.exports = router;

const express = require("express")
const { executeQuery } = require("../config/database")
const { authenticateToken, requirePermission } = require("../middleware/auth")
const { logSecurityEvent } = require("../utils/security")
const { evaluatePolicy, createPolicy, validatePolicy } = require("../utils/abac")

const router = express.Router()

// Aplicar autenticación a todas las rutas
router.use(authenticateToken)

// Evaluar acceso basado en políticas ABAC
router.post("/evaluate", async (req, res) => {
  try {
    const { resource, action, context = {} } = req.body

    if (!resource || !action) {
      return res.status(400).json({ error: "Recurso y acción son requeridos" })
    }

    // Obtener información del usuario y sus roles
    const userRoles = await executeQuery(
      `
      SELECT r.name, r.permissions 
      FROM user_roles ur 
      JOIN roles r ON ur.role_id = r.id 
      WHERE ur.user_id = ?
    `,
      [req.user.id],
    )

    // Construir contexto completo para evaluación
    const evaluationContext = {
      user: {
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        roles: userRoles.map((r) => r.name),
      },
      request: {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
        timestamp: new Date().toISOString(),
        resource: resource,
        action: action,
      },
      environment: {
        time: new Date().getHours(),
        dayOfWeek: new Date().getDay(),
        ...context,
      },
    }

    // Evaluar políticas
    const decision = await evaluatePolicy(evaluationContext, resource, action, userRoles)

    await logSecurityEvent(req.user.id, "abac_evaluation", resource, req.ip, req.get("User-Agent"), decision.permit, {
      resource,
      action,
      decision: decision.decision,
      reasons: decision.reasons,
    })

    res.json({
      permit: decision.permit,
      decision: decision.decision,
      reasons: decision.reasons,
      context: evaluationContext,
    })
  } catch (error) {
    console.error("Error evaluando política ABAC:", error)
    res.status(500).json({ error: "Error evaluando política de acceso" })
  }
})

// Obtener políticas de acceso
router.get("/policies", requirePermission("security", "read"), async (req, res) => {
  try {
    const policies = await executeQuery(`
      SELECT * FROM access_policies 
      ORDER BY priority DESC, created_at DESC
    `)

    const parsedPolicies = policies.map((policy) => ({
      ...policy,
      conditions: JSON.parse(policy.conditions),
      actions: JSON.parse(policy.actions),
    }))

    res.json(parsedPolicies)
  } catch (error) {
    console.error("Error obteniendo políticas:", error)
    res.status(500).json({ error: "Error obteniendo políticas" })
  }
})

// Crear nueva política de acceso
router.post("/policies", requirePermission("security", "configure"), async (req, res) => {
  try {
    const { name, description, resource, conditions, actions, effect, priority = 0 } = req.body

    // Validar política
    const validation = validatePolicy({ name, resource, conditions, actions, effect })
    if (!validation.isValid) {
      return res.status(400).json({ error: validation.errors })
    }

    // Crear política
    const result = await executeQuery(
      "INSERT INTO access_policies (name, description, resource, conditions, actions, effect, priority, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [name, description, resource, JSON.stringify(conditions), JSON.stringify(actions), effect, priority, req.user.id],
    )

    await logSecurityEvent(req.user.id, "policy_created", "access_policies", req.ip, req.get("User-Agent"), true, {
      policyId: result.insertId,
      policyName: name,
      resource,
      effect,
    })

    res.status(201).json({
      message: "Política creada exitosamente",
      policyId: result.insertId,
    })
  } catch (error) {
    console.error("Error creando política:", error)
    res.status(500).json({ error: "Error creando política" })
  }
})

// Actualizar política
router.put("/policies/:id", requirePermission("security", "configure"), async (req, res) => {
  try {
    const policyId = req.params.id
    const { name, description, resource, conditions, actions, effect, priority } = req.body

    // Verificar que la política existe
    const existingPolicy = await executeQuery("SELECT * FROM access_policies WHERE id = ?", [policyId])

    if (existingPolicy.length === 0) {
      return res.status(404).json({ error: "Política no encontrada" })
    }

    // Validar política
    const validation = validatePolicy({ name, resource, conditions, actions, effect })
    if (!validation.isValid) {
      return res.status(400).json({ error: validation.errors })
    }

    // Actualizar política
    await executeQuery(
      "UPDATE access_policies SET name = ?, description = ?, resource = ?, conditions = ?, actions = ?, effect = ?, priority = ? WHERE id = ?",
      [name, description, resource, JSON.stringify(conditions), JSON.stringify(actions), effect, priority, policyId],
    )

    await logSecurityEvent(req.user.id, "policy_updated", "access_policies", req.ip, req.get("User-Agent"), true, {
      policyId: policyId,
      policyName: name,
      oldData: existingPolicy[0],
    })

    res.json({ message: "Política actualizada exitosamente" })
  } catch (error) {
    console.error("Error actualizando política:", error)
    res.status(500).json({ error: "Error actualizando política" })
  }
})

// Eliminar política
router.delete("/policies/:id", requirePermission("security", "configure"), async (req, res) => {
  try {
    const policyId = req.params.id

    // Verificar que la política existe
    const existingPolicy = await executeQuery("SELECT * FROM access_policies WHERE id = ?", [policyId])

    if (existingPolicy.length === 0) {
      return res.status(404).json({ error: "Política no encontrada" })
    }

    // Eliminar política
    await executeQuery("DELETE FROM access_policies WHERE id = ?", [policyId])

    await logSecurityEvent(req.user.id, "policy_deleted", "access_policies", req.ip, req.get("User-Agent"), true, {
      policyId: policyId,
      policyName: existingPolicy[0].name,
    })

    res.json({ message: "Política eliminada exitosamente" })
  } catch (error) {
    console.error("Error eliminando política:", error)
    res.status(500).json({ error: "Error eliminando política" })
  }
})

// Obtener historial de decisiones ABAC
router.get("/decisions", requirePermission("security", "analyze"), async (req, res) => {
  try {
    const { limit = 100, offset = 0, userId, resource, action } = req.query

    let query = `
      SELECT sl.*, u.username 
      FROM security_logs sl
      LEFT JOIN users u ON sl.user_id = u.id
      WHERE sl.action = 'abac_evaluation'
    `
    const params = []

    if (userId) {
      query += " AND sl.user_id = ?"
      params.push(userId)
    }

    if (resource) {
      query += " AND sl.resource = ?"
      params.push(resource)
    }

    if (action) {
      query += " AND JSON_EXTRACT(sl.details, '$.action') = ?"
      params.push(action)
    }

    query += " ORDER BY sl.created_at DESC LIMIT ? OFFSET ?"
    params.push(Number.parseInt(limit), Number.parseInt(offset))

    const decisions = await executeQuery(query, params)

    const parsedDecisions = decisions.map((decision) => ({
      ...decision,
      details: JSON.parse(decision.details),
    }))

    res.json(parsedDecisions)
  } catch (error) {
    console.error("Error obteniendo decisiones:", error)
    res.status(500).json({ error: "Error obteniendo historial de decisiones" })
  }
})

module.exports = router

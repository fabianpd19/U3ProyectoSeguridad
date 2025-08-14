const express = require("express")
const { executeQuery, executeTransaction } = require("../config/database")
const { authenticateToken, requirePermission } = require("../middleware/auth")
const { logSecurityEvent } = require("../utils/security")
const { validateInput, sanitizeInput } = require("../utils/validation")

const router = express.Router()

// Aplicar autenticación a todas las rutas
router.use(authenticateToken)

// Obtener todos los roles
router.get("/", requirePermission("roles", "read"), async (req, res) => {
  try {
    const roles = await executeQuery(`
      SELECT r.*, 
             COUNT(ur.user_id) as user_count,
             GROUP_CONCAT(u.username) as assigned_users
      FROM roles r
      LEFT JOIN user_roles ur ON r.id = ur.role_id
      LEFT JOIN users u ON ur.user_id = u.id
      GROUP BY r.id
      ORDER BY r.name
    `)

    // Parsear permisos JSON
    const rolesWithPermissions = roles.map((role) => ({
      ...role,
      permissions: JSON.parse(role.permissions),
      assigned_users: role.assigned_users ? role.assigned_users.split(",") : [],
    }))

    await logSecurityEvent(req.user.id, "roles_viewed", "roles", req.ip, req.get("User-Agent"), true)

    res.json(rolesWithPermissions)
  } catch (error) {
    console.error("Error obteniendo roles:", error)
    res.status(500).json({ error: "Error obteniendo roles" })
  }
})

// Obtener rol específico
router.get("/:id", requirePermission("roles", "read"), async (req, res) => {
  try {
    const roleId = req.params.id

    const roles = await executeQuery(
      `
      SELECT r.*, 
             COUNT(ur.user_id) as user_count
      FROM roles r
      LEFT JOIN user_roles ur ON r.id = ur.role_id
      WHERE r.id = ?
      GROUP BY r.id
    `,
      [roleId],
    )

    if (roles.length === 0) {
      return res.status(404).json({ error: "Rol no encontrado" })
    }

    const role = {
      ...roles[0],
      permissions: JSON.parse(roles[0].permissions),
    }

    // Obtener usuarios asignados
    const assignedUsers = await executeQuery(
      `
      SELECT u.id, u.username, u.email, ur.assigned_at
      FROM user_roles ur
      JOIN users u ON ur.user_id = u.id
      WHERE ur.role_id = ?
    `,
      [roleId],
    )

    role.assigned_users = assignedUsers

    res.json(role)
  } catch (error) {
    console.error("Error obteniendo rol:", error)
    res.status(500).json({ error: "Error obteniendo rol" })
  }
})

// Crear nuevo rol
router.post("/", requirePermission("roles", "create"), async (req, res) => {
  try {
    const { name, description, permissions } = req.body

    // Validar entrada
    const validation = validateInput({ name, description })
    if (!validation.isValid) {
      return res.status(400).json({ error: validation.errors })
    }

    // Sanitizar datos
    const sanitizedData = sanitizeInput({ name, description })

    // Validar estructura de permisos
    if (!permissions || typeof permissions !== "object") {
      return res.status(400).json({ error: "Estructura de permisos inválida" })
    }

    // Verificar que el rol no exista
    const existingRole = await executeQuery("SELECT id FROM roles WHERE name = ?", [sanitizedData.name])

    if (existingRole.length > 0) {
      return res.status(400).json({ error: "El rol ya existe" })
    }

    // Crear rol
    const result = await executeQuery("INSERT INTO roles (name, description, permissions) VALUES (?, ?, ?)", [
      sanitizedData.name,
      sanitizedData.description,
      JSON.stringify(permissions),
    ])

    await logSecurityEvent(req.user.id, "role_created", "roles", req.ip, req.get("User-Agent"), true, {
      roleId: result.insertId,
      roleName: sanitizedData.name,
    })

    res.status(201).json({
      message: "Rol creado exitosamente",
      roleId: result.insertId,
    })
  } catch (error) {
    console.error("Error creando rol:", error)
    res.status(500).json({ error: "Error creando rol" })
  }
})

// Actualizar rol
router.put("/:id", requirePermission("roles", "update"), async (req, res) => {
  try {
    const roleId = req.params.id
    const { name, description, permissions } = req.body

    // Validar que el rol existe
    const existingRole = await executeQuery("SELECT * FROM roles WHERE id = ?", [roleId])

    if (existingRole.length === 0) {
      return res.status(404).json({ error: "Rol no encontrado" })
    }

    // Validar entrada
    const validation = validateInput({ name, description })
    if (!validation.isValid) {
      return res.status(400).json({ error: validation.errors })
    }

    // Sanitizar datos
    const sanitizedData = sanitizeInput({ name, description })

    // Validar estructura de permisos
    if (!permissions || typeof permissions !== "object") {
      return res.status(400).json({ error: "Estructura de permisos inválida" })
    }

    // Verificar que no haya otro rol con el mismo nombre
    const duplicateRole = await executeQuery("SELECT id FROM roles WHERE name = ? AND id != ?", [
      sanitizedData.name,
      roleId,
    ])

    if (duplicateRole.length > 0) {
      return res.status(400).json({ error: "Ya existe otro rol con ese nombre" })
    }

    // Actualizar rol
    await executeQuery("UPDATE roles SET name = ?, description = ?, permissions = ? WHERE id = ?", [
      sanitizedData.name,
      sanitizedData.description,
      JSON.stringify(permissions),
      roleId,
    ])

    await logSecurityEvent(req.user.id, "role_updated", "roles", req.ip, req.get("User-Agent"), true, {
      roleId: roleId,
      roleName: sanitizedData.name,
      oldData: existingRole[0],
    })

    res.json({ message: "Rol actualizado exitosamente" })
  } catch (error) {
    console.error("Error actualizando rol:", error)
    res.status(500).json({ error: "Error actualizando rol" })
  }
})

// Eliminar rol
router.delete("/:id", requirePermission("roles", "delete"), async (req, res) => {
  try {
    const roleId = req.params.id

    // Verificar que el rol existe
    const existingRole = await executeQuery("SELECT * FROM roles WHERE id = ?", [roleId])

    if (existingRole.length === 0) {
      return res.status(404).json({ error: "Rol no encontrado" })
    }

    // Verificar que no sea un rol del sistema (admin, user, etc.)
    const systemRoles = ["admin", "security_analyst", "user"]
    if (systemRoles.includes(existingRole[0].name)) {
      return res.status(400).json({ error: "No se puede eliminar un rol del sistema" })
    }

    // Verificar que no tenga usuarios asignados
    const assignedUsers = await executeQuery("SELECT COUNT(*) as count FROM user_roles WHERE role_id = ?", [roleId])

    if (assignedUsers[0].count > 0) {
      return res.status(400).json({
        error: "No se puede eliminar un rol que tiene usuarios asignados",
        assignedUsers: assignedUsers[0].count,
      })
    }

    // Eliminar rol
    await executeQuery("DELETE FROM roles WHERE id = ?", [roleId])

    await logSecurityEvent(req.user.id, "role_deleted", "roles", req.ip, req.get("User-Agent"), true, {
      roleId: roleId,
      roleName: existingRole[0].name,
    })

    res.json({ message: "Rol eliminado exitosamente" })
  } catch (error) {
    console.error("Error eliminando rol:", error)
    res.status(500).json({ error: "Error eliminando rol" })
  }
})

// Asignar rol a usuario
router.post("/:roleId/assign/:userId", requirePermission("roles", "update"), async (req, res) => {
  try {
    const { roleId, userId } = req.params

    // Verificar que el rol y usuario existen
    const role = await executeQuery("SELECT name FROM roles WHERE id = ?", [roleId])
    const user = await executeQuery("SELECT username FROM users WHERE id = ?", [userId])

    if (role.length === 0) {
      return res.status(404).json({ error: "Rol no encontrado" })
    }

    if (user.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" })
    }

    // Verificar que no esté ya asignado
    const existingAssignment = await executeQuery("SELECT id FROM user_roles WHERE user_id = ? AND role_id = ?", [
      userId,
      roleId,
    ])

    if (existingAssignment.length > 0) {
      return res.status(400).json({ error: "El usuario ya tiene este rol asignado" })
    }

    // Asignar rol
    await executeQuery("INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)", [
      userId,
      roleId,
      req.user.id,
    ])

    await logSecurityEvent(req.user.id, "role_assigned", "user_roles", req.ip, req.get("User-Agent"), true, {
      targetUserId: userId,
      targetUsername: user[0].username,
      roleId: roleId,
      roleName: role[0].name,
    })

    res.json({ message: "Rol asignado exitosamente" })
  } catch (error) {
    console.error("Error asignando rol:", error)
    res.status(500).json({ error: "Error asignando rol" })
  }
})

// Remover rol de usuario
router.delete("/:roleId/unassign/:userId", requirePermission("roles", "update"), async (req, res) => {
  try {
    const { roleId, userId } = req.params

    // Verificar que la asignación existe
    const assignment = await executeQuery(
      `
      SELECT ur.*, r.name as role_name, u.username
      FROM user_roles ur
      JOIN roles r ON ur.role_id = r.id
      JOIN users u ON ur.user_id = u.id
      WHERE ur.user_id = ? AND ur.role_id = ?
    `,
      [userId, roleId],
    )

    if (assignment.length === 0) {
      return res.status(404).json({ error: "Asignación de rol no encontrada" })
    }

    // Verificar que no sea el último admin
    if (assignment[0].role_name === "admin") {
      const adminCount = await executeQuery(
        "SELECT COUNT(*) as count FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE r.name = 'admin'",
      )

      if (adminCount[0].count <= 1) {
        return res.status(400).json({ error: "No se puede remover el último administrador" })
      }
    }

    // Remover asignación
    await executeQuery("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", [userId, roleId])

    await logSecurityEvent(req.user.id, "role_unassigned", "user_roles", req.ip, req.get("User-Agent"), true, {
      targetUserId: userId,
      targetUsername: assignment[0].username,
      roleId: roleId,
      roleName: assignment[0].role_name,
    })

    res.json({ message: "Rol removido exitosamente" })
  } catch (error) {
    console.error("Error removiendo rol:", error)
    res.status(500).json({ error: "Error removiendo rol" })
  }
})

module.exports = router

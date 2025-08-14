const jwt = require("jsonwebtoken");
const { executeQuery } = require("../config/database");
const { logSecurityEvent } = require("../utils/security");

// Middleware de autenticación JWT
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      await logSecurityEvent(
        null,
        "access_denied",
        "missing_token",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Token de acceso requerido" });
    }

    // Verificar JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Verificar que la sesión siga activa
    const sessions = await executeQuery(
      "SELECT s.*, u.username, u.email, u.status FROM user_sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ? AND s.is_active = TRUE AND s.expires_at > NOW()",
      [decoded.sessionId]
    );

    if (sessions.length === 0) {
      await logSecurityEvent(
        decoded.userId,
        "access_denied",
        "invalid_session",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Sesión inválida o expirada" });
    }

    const session = sessions[0];

    // Verificar que el usuario siga activo
    if (session.status !== "active") {
      await logSecurityEvent(
        decoded.userId,
        "access_denied",
        "user_inactive",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Usuario inactivo" });
    }

    // Verificar IP (opcional, para mayor seguridad)
    if (
      process.env.STRICT_IP_VALIDATION === "true" &&
      session.ip_address !== req.ip
    ) {
      await logSecurityEvent(
        decoded.userId,
        "access_denied",
        "ip_mismatch",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Acceso desde IP no autorizada" });
    }

    // Agregar información del usuario al request
    req.user = {
      id: decoded.userId,
      username: session.username,
      email: session.email,
      sessionId: decoded.sessionId,
    };

    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      await logSecurityEvent(
        null,
        "access_denied",
        "invalid_token",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Token inválido" });
    }

    if (error.name === "TokenExpiredError") {
      await logSecurityEvent(
        null,
        "access_denied",
        "expired_token",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Token expirado" });
    }

    console.error("Error en autenticación:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
}

// Middleware para verificar roles específicos
function requireRole(requiredRoles) {
  return async (req, res, next) => {
    try {
      const userId = req.user.id;

      // Obtener roles del usuario
      const userRoles = await executeQuery(
        `
        SELECT r.name, r.permissions 
        FROM user_roles ur 
        JOIN roles r ON ur.role_id = r.id 
        WHERE ur.user_id = ?
      `,
        [userId]
      );

      if (userRoles.length === 0) {
        await logSecurityEvent(
          userId,
          "access_denied",
          "no_roles",
          req.ip,
          req.get("User-Agent"),
          false
        );
        return res.status(403).json({ error: "Sin roles asignados" });
      }

      // Verificar si el usuario tiene alguno de los roles requeridos
      const hasRequiredRole = userRoles.some((role) =>
        requiredRoles.includes(role.name)
      );

      if (!hasRequiredRole) {
        await logSecurityEvent(
          userId,
          "access_denied",
          "insufficient_role",
          req.ip,
          req.get("User-Agent"),
          false,
          {
            requiredRoles,
            userRoles: userRoles.map((r) => r.name),
          }
        );
        return res.status(403).json({ error: "Permisos insuficientes" });
      }

      // Agregar roles al request para uso posterior
      req.user.roles = userRoles;

      next();
    } catch (error) {
      console.error("Error verificando roles:", error);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  };
}

// Middleware para verificar permisos específicos (ABAC)
function requirePermission(resource, action) {
  return async (req, res, next) => {
    try {
      const userId = req.user.id;

      // Obtener permisos del usuario
      const userRoles = await executeQuery(
        `
        SELECT r.permissions 
        FROM user_roles ur 
        JOIN roles r ON ur.role_id = r.id 
        WHERE ur.user_id = ?
      `,
        [userId]
      );

      let hasPermission = false;

      // Verificar permisos en cada rol
      for (const role of userRoles) {
        const permissions = JSON.parse(role.permissions);

        if (permissions[resource] && permissions[resource].includes(action)) {
          hasPermission = true;
          break;
        }
      }

      if (!hasPermission) {
        await logSecurityEvent(
          userId,
          "access_denied",
          "insufficient_permission",
          req.ip,
          req.get("User-Agent"),
          false,
          {
            resource,
            action,
            userRoles: userRoles.map((r) => JSON.parse(r.permissions)),
          }
        );
        return res
          .status(403)
          .json({ error: `Permiso denegado para ${action} en ${resource}` });
      }

      next();
    } catch (error) {
      console.error("Error verificando permisos:", error);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  };
}

module.exports = {
  authenticateToken,
  requireRole,
  requirePermission,
};

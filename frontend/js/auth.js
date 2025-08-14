// Gestión de autenticación

class AuthManager {
  constructor() {
    this.currentUser = Storage.get("currentUser")
    this.token = Storage.get("authToken")
  }

  async login(credentials) {
    try {
      const response = await Http.post("/auth/login", credentials)

      if (response.requiresTwoFactor) {
        return { requiresTwoFactor: true }
      }

      this.setAuthData(response.token, response.user)
      return { success: true, user: response.user }
    } catch (error) {
      throw error
    }
  }

  async register(userData) {
    try {
      const response = await Http.post("/auth/register", userData)
      return response
    } catch (error) {
      throw error
    }
  }

  async logout() {
    try {
      if (this.token) {
        await Http.post("/auth/logout")
      }
    } catch (error) {
      console.error("Error during logout:", error)
    } finally {
      this.clearAuthData()
      window.location.href = "/"
    }
  }

  async getCaptcha() {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/captcha`, {
        credentials: "include",
      })
      return await response.json()
    } catch (error) {
      console.error("Error getting captcha:", error)
      throw error
    }
  }

  async setup2FA() {
    try {
      const response = await Http.post("/auth/setup-2fa")
      return response
    } catch (error) {
      throw error
    }
  }

  async verify2FA(token) {
    try {
      const response = await Http.post("/auth/verify-2fa", { token })
      return response
    } catch (error) {
      throw error
    }
  }

  async disable2FA(password, twoFactorCode) {
    try {
      const response = await Http.post("/auth/disable-2fa", {
        password,
        twoFactorCode,
      })
      return response
    } catch (error) {
      throw error
    }
  }

  setAuthData(token, user) {
    this.token = token
    this.currentUser = user
    Storage.set("authToken", token)
    Storage.set("currentUser", user)
  }

  clearAuthData() {
    this.token = null
    this.currentUser = null
    Storage.remove("authToken")
    Storage.remove("currentUser")
  }

  isAuthenticated() {
    return !!(this.token && this.currentUser)
  }

  getCurrentUser() {
    return this.currentUser
  }

  hasPermission(resource, action) {
    // Esta función se implementaría con la lógica ABAC del backend
    // Por ahora, verificamos roles básicos
    if (!this.currentUser || !this.currentUser.roles) {
      return false
    }

    // Los administradores tienen todos los permisos
    if (this.currentUser.roles.includes("admin")) {
      return true
    }

    // Lógica básica de permisos por rol
    const rolePermissions = {
      security_analyst: {
        security: ["read", "analyze"],
        vulnerabilities: ["scan", "read", "analyze"],
        certificates: ["read"],
        users: ["read"],
      },
      user: {
        profile: ["read", "update"],
        certificates: ["read"],
      },
    }

    for (const role of this.currentUser.roles) {
      const permissions = rolePermissions[role]
      if (permissions && permissions[resource] && permissions[resource].includes(action)) {
        return true
      }
    }

    return false
  }

  requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.href = "/"
      return false
    }
    return true
  }

  requirePermission(resource, action) {
    if (!this.requireAuth()) {
      return false
    }

    if (!this.hasPermission(resource, action)) {
      UI.showAlert("No tienes permisos para realizar esta acción", "error")
      return false
    }

    return true
  }
}

// Instancia global del gestor de autenticación
window.Auth = new AuthManager()

// Verificar autenticación al cargar la página
document.addEventListener("DOMContentLoaded", () => {
  // Si estamos en la página de login y ya estamos autenticados, redirigir al dashboard
  if (window.location.pathname === "/" || window.location.pathname === "/index.html") {
    if (Auth.isAuthenticated()) {
      window.location.href = "/dashboard.html"
    }
  } else {
    // Para cualquier otra página, verificar autenticación
    if (!Auth.isAuthenticated()) {
      window.location.href = "/"
    }
  }
})

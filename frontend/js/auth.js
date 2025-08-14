// Gestión de autenticación
const Http = {
  post: async (url, data) => {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include", // Importante para cookies de sesión
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.error || `HTTP ${response.status}: ${response.statusText}`
      );
    }

    return response.json();
  },

  get: async (url) => {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.error || `HTTP ${response.status}: ${response.statusText}`
      );
    }

    return response.json();
  },
};

// Cambia esta URL por tu URL real del backend
const API_BASE_URL = "http://localhost:3000/api";

const UI = {
  showAlert: (message, type) => {
    // Mejorar esto con un sistema de alertas más sofisticado
    const alertContainer = document.getElementById("alertContainer");
    if (alertContainer) {
      const alertDiv = document.createElement("div");
      alertDiv.className = `alert alert-${type}`;
      alertDiv.textContent = message;
      alertContainer.appendChild(alertDiv);

      // Auto-remover después de 5 segundos
      setTimeout(() => {
        if (alertDiv.parentNode) {
          alertDiv.parentNode.removeChild(alertDiv);
        }
      }, 5000);
    } else {
      // Fallback a alert nativo
      alert(`${type.toUpperCase()}: ${message}`);
    }
  },

  setLoading: (button, isLoading) => {
    if (!button) return;

    const btnText = button.querySelector(".btn-text");
    const btnLoading = button.querySelector(".btn-loading");

    if (isLoading) {
      button.disabled = true;
      if (btnText) btnText.style.display = "none";
      if (btnLoading) btnLoading.style.display = "inline";
    } else {
      button.disabled = false;
      if (btnText) btnText.style.display = "inline";
      if (btnLoading) btnLoading.style.display = "none";
    }
  },
};

const Storage = {
  get: (key) => {
    try {
      const item = localStorage.getItem(key);
      if (!item) return null;

      // Verificar si es un JWT token (comienza con eyJ)
      if (typeof item === "string" && item.startsWith("eyJ")) {
        return item; // Retornar el token directamente sin hacer JSON.parse
      }

      // Intentar parsear como JSON
      try {
        return JSON.parse(item);
      } catch (parseError) {
        // Si no es JSON válido, retornar el string tal como está
        console.warn(
          `Item '${key}' is not valid JSON, returning as string:`,
          parseError
        );
        return item;
      }
    } catch (error) {
      console.error("Error getting stored data:", error);
      return null;
    }
  },
  set: (key, value) => {
    try {
      localStorage.setItem(
        key,
        typeof value === "string" ? value : JSON.stringify(value)
      );
    } catch (error) {
      console.error("Error storing data:", error);
    }
  },
  remove: (key) => localStorage.removeItem(key),
};

class AuthManager {
  constructor() {
    this.currentUser = Storage.get("currentUser");
    this.token = Storage.get("authToken");
  }

  async login(credentials) {
    try {
      const response = await Http.post(`${API_BASE_URL}/auth/login`, {
        username: credentials.username,
        password: credentials.password,
        captcha: credentials.captcha,
        captchaToken: credentials.captchaToken, // Token del captcha del servidor
        twoFactorCode: credentials.twoFactorCode,
      });

      if (response.requiresTwoFactor) {
        return { requiresTwoFactor: true };
      }

      this.setAuthData(response.token, response.user);
      return { success: true, user: response.user, token: response.token };
    } catch (error) {
      console.error("Login error:", error);
      throw error;
    }
  }

  async register(userData) {
    try {
      const response = await Http.post(`${API_BASE_URL}/auth/register`, {
        username: userData.username,
        email: userData.email,
        password: userData.password,
        captcha: userData.captcha,
        captchaToken: userData.captchaToken,
      });
      return response;
    } catch (error) {
      console.error("Register error:", error);
      throw error;
    }
  }

  async logout() {
    try {
      if (this.token) {
        await Http.post(`${API_BASE_URL}/auth/logout`);
      }
    } catch (error) {
      console.error("Error during logout:", error);
    } finally {
      this.clearAuthData();
      window.location.href = "/frontend/index.html";
    }
  }

  async getCaptcha() {
    try {
      const response = await Http.get(`${API_BASE_URL}/auth/captcha`);
      return response;
    } catch (error) {
      console.error("Error getting captcha:", error);
      throw error;
    }
  }

  async setup2FA() {
    try {
      const response = await Http.post(`${API_BASE_URL}/auth/setup-2fa`);
      return response;
    } catch (error) {
      throw error;
    }
  }

  async verify2FA(token) {
    try {
      const response = await Http.post(`${API_BASE_URL}/auth/verify-2fa`, {
        token,
      });
      return response;
    } catch (error) {
      throw error;
    }
  }

  async disable2FA(password, twoFactorCode) {
    try {
      const response = await Http.post(`${API_BASE_URL}/auth/disable-2fa`, {
        password,
        twoFactorCode,
      });
      return response;
    } catch (error) {
      throw error;
    }
  }

  setAuthData(token, user) {
    this.token = token;
    this.currentUser = user;
    Storage.set("authToken", token);
    Storage.set("currentUser", user);
  }

  clearAuthData() {
    this.token = null;
    this.currentUser = null;
    Storage.remove("authToken");
    Storage.remove("currentUser");
  }

  isAuthenticated() {
    return !!(this.token && this.currentUser);
  }

  getCurrentUser() {
    return this.currentUser;
  }

  hasPermission(resource, action) {
    if (!this.currentUser || !this.currentUser.roles) {
      return false;
    }

    if (this.currentUser.roles.includes("admin")) {
      return true;
    }

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
    };

    for (const role of this.currentUser.roles) {
      const permissions = rolePermissions[role];
      if (
        permissions &&
        permissions[resource] &&
        permissions[resource].includes(action)
      ) {
        return true;
      }
    }
    return false;
  }

  requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.href = "/frontend/index.html";
      return false;
    }
    return true;
  }

  requirePermission(resource, action) {
    if (!this.requireAuth()) {
      return false;
    }
    if (!this.hasPermission(resource, action)) {
      UI.showAlert("No tienes permisos para realizar esta acción", "error");
      return false;
    }
    return true;
  }
}

// Instancia global del gestor de autenticación
window.AuthManager = new AuthManager();
window.API_BASE_URL = API_BASE_URL;
window.UI = UI;
window.Storage = Storage;

// Verificar autenticación al cargar la página
document.addEventListener("DOMContentLoaded", () => {
  // Si estamos en la página de login y ya estamos autenticados, redirigir al dashboard
  if (
    window.location.pathname === "/" ||
    window.location.pathname === "/index.html" ||
    window.location.pathname === "/frontend/index.html"
  ) {
    if (window.AuthManager.isAuthenticated()) {
      window.location.href = "/frontend/dashboard.html";
    }
  } else {
    // Para cualquier otra página, verificar autenticación
    if (!window.AuthManager.isAuthenticated()) {
      window.location.href = "/frontend/index.html";
    }
  }
});

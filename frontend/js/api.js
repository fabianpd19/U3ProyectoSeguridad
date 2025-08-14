// API Manager - Sistema centralizado para manejo de APIs
class APIManager {
  constructor() {
    this.baseURL = window.API_BASE_URL || "/api";
    this.defaultHeaders = {
      "Content-Type": "application/json",
    };
  }

  // Método privado para obtener headers con autenticación
  getAuthHeaders() {
    const token = window.Storage?.get("authToken");
    return {
      ...this.defaultHeaders,
      ...(token && { Authorization: `Bearer ${token}` }),
    };
  }

  // Método privado para manejar respuestas
  async handleResponse(response) {
    if (response.status === 401) {
      // Token expirado o inválido
      window.Logger?.warn("Token expirado, redirigiendo al login");
      window.AuthManager?.logout();
      return;
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.error || `HTTP ${response.status}: ${response.statusText}`
      );
    }

    return response.json();
  }

  // Métodos HTTP genéricos
  async get(endpoint, options = {}) {
    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        method: "GET",
        headers: this.getAuthHeaders(),
        credentials: "include",
        ...options,
      });
      return this.handleResponse(response);
    } catch (error) {
      window.Logger?.error(`GET ${endpoint} failed:`, error);
      throw error;
    }
  }

  async post(endpoint, data = {}, options = {}) {
    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        method: "POST",
        headers: this.getAuthHeaders(),
        credentials: "include",
        body: JSON.stringify(data),
        ...options,
      });
      return this.handleResponse(response);
    } catch (error) {
      window.Logger?.error(`POST ${endpoint} failed:`, error);
      throw error;
    }
  }

  async put(endpoint, data = {}, options = {}) {
    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        method: "PUT",
        headers: this.getAuthHeaders(),
        credentials: "include",
        body: JSON.stringify(data),
        ...options,
      });
      return this.handleResponse(response);
    } catch (error) {
      window.Logger?.error(`PUT ${endpoint} failed:`, error);
      throw error;
    }
  }

  async delete(endpoint, options = {}) {
    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        method: "DELETE",
        headers: this.getAuthHeaders(),
        credentials: "include",
        ...options,
      });
      return this.handleResponse(response);
    } catch (error) {
      window.Logger?.error(`DELETE ${endpoint} failed:`, error);
      throw error;
    }
  }

  // Métodos específicos para Security
  security = {
    getDashboard: () => this.get("/security/dashboard"),
    getLogs: (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.get(`/security/logs${queryString ? `?${queryString}` : ""}`);
    },
    getRiskAnalysis: (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.get(
        `/security/risk-analysis${queryString ? `?${queryString}` : ""}`
      );
    },
    generateReport: (data) => this.post("/security/reports", data),
    getAlerts: () => this.get("/security/alerts"),
    configureAlert: (data) => this.post("/security/alerts/configure", data),
  };

  // Métodos específicos para Vulnerabilidades
  vulnerabilities = {
    getScans: (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.get(
        `/vulnerabilities/scans${queryString ? `?${queryString}` : ""}`
      );
    },
    startScan: (data) => this.post("/vulnerabilities/scans", data),
    getScan: (id) => this.get(`/vulnerabilities/scans/${id}`),
    getAnalysis: () => this.get("/vulnerabilities/analysis"),
    generateReport: (data) => this.post("/vulnerabilities/reports", data),
    getStats: () => this.get("/vulnerabilities/stats"),
  };

  // Métodos específicos para Certificados
  certificates = {
    getAll: (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.get(`/certificates${queryString ? `?${queryString}` : ""}`);
    },
    create: (data) => this.post("/certificates/create", data),
    validate: (data) => this.post("/certificates/validate", data),
    getById: (id) => this.get(`/certificates/${id}`),
    revoke: (id) => this.put(`/certificates/${id}/revoke`),
  };

  // Métodos específicos para Usuarios y Roles
  users = {
    getAll: (params = {}) => {
      const queryString = new URLSearchParams(params).toString();
      return this.get(`/users${queryString ? `?${queryString}` : ""}`);
    },
    getById: (id) => this.get(`/users/${id}`),
    create: (data) => this.post("/users", data),
    update: (id, data) => this.put(`/users/${id}`, data),
    delete: (id) => this.delete(`/users/${id}`),
  };

  roles = {
    getAll: () => this.get("/roles"),
    getById: (id) => this.get(`/roles/${id}`),
    create: (data) => this.post("/roles", data),
    update: (id, data) => this.put(`/roles/${id}`, data),
    delete: (id) => this.delete(`/roles/${id}`),
  };

  // Método para verificar estado del servidor
  async healthCheck() {
    try {
      return await this.get("/health");
    } catch (error) {
      window.Logger?.error("Health check failed:", error);
      throw error;
    }
  }
}

// Instancia global
window.API = new APIManager();

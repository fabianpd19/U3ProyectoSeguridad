// Utilidades generales para la Plataforma Web Segura

// Configuración de la API
const API_BASE_URL =
  window.location.protocol + "//" + window.location.hostname + ":" + (window.location.port || "3000") + "/api"

// Utilidades de almacenamiento
const Storage = {
  set: (key, value) => {
    try {
      localStorage.setItem(key, JSON.stringify(value))
    } catch (error) {
      console.error("Error guardando en localStorage:", error)
    }
  },

  get: (key, defaultValue = null) => {
    try {
      const item = localStorage.getItem(key)
      return item ? JSON.parse(item) : defaultValue
    } catch (error) {
      console.error("Error leyendo de localStorage:", error)
      return defaultValue
    }
  },

  remove: (key) => {
    try {
      localStorage.removeItem(key)
    } catch (error) {
      console.error("Error removiendo de localStorage:", error)
    }
  },

  clear: () => {
    try {
      localStorage.clear()
    } catch (error) {
      console.error("Error limpiando localStorage:", error)
    }
  },
}

// Utilidades de fecha y tiempo
const DateUtils = {
  formatDate: (date) => {
    if (!date) return "-"
    const d = new Date(date)
    return d.toLocaleDateString("es-ES", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    })
  },

  formatDateTime: (date) => {
    if (!date) return "-"
    const d = new Date(date)
    return d.toLocaleString("es-ES", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    })
  },

  formatRelativeTime: (date) => {
    if (!date) return "-"
    const now = new Date()
    const d = new Date(date)
    const diffMs = now - d
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMs / 3600000)
    const diffDays = Math.floor(diffMs / 86400000)

    if (diffMins < 1) return "Ahora mismo"
    if (diffMins < 60) return `Hace ${diffMins} minuto${diffMins > 1 ? "s" : ""}`
    if (diffHours < 24) return `Hace ${diffHours} hora${diffHours > 1 ? "s" : ""}`
    if (diffDays < 7) return `Hace ${diffDays} día${diffDays > 1 ? "s" : ""}`

    return DateUtils.formatDate(date)
  },
}

// Utilidades de validación
const Validation = {
  email: (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return re.test(email)
  },

  password: (password) => {
    const minLength = 8
    const hasUpperCase = /[A-Z]/.test(password)
    const hasLowerCase = /[a-z]/.test(password)
    const hasNumbers = /\d/.test(password)
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password)

    const errors = []

    if (password.length < minLength) {
      errors.push(`Mínimo ${minLength} caracteres`)
    }
    if (!hasUpperCase) {
      errors.push("Al menos una mayúscula")
    }
    if (!hasLowerCase) {
      errors.push("Al menos una minúscula")
    }
    if (!hasNumbers) {
      errors.push("Al menos un número")
    }
    if (!hasSpecialChar) {
      errors.push("Al menos un carácter especial")
    }

    let strength = 0
    if (password.length >= minLength) strength++
    if (hasUpperCase) strength++
    if (hasLowerCase) strength++
    if (hasNumbers) strength++
    if (hasSpecialChar) strength++

    const strengthLevels = ["muy débil", "débil", "media", "fuerte", "muy fuerte"]

    return {
      isValid: errors.length === 0,
      errors: errors,
      strength: strengthLevels[Math.min(strength, 4)],
    }
  },

  username: (username) => {
    const minLength = 3
    const maxLength = 50
    const validChars = /^[a-zA-Z0-9_]+$/

    const errors = []

    if (username.length < minLength) {
      errors.push(`Mínimo ${minLength} caracteres`)
    }
    if (username.length > maxLength) {
      errors.push(`Máximo ${maxLength} caracteres`)
    }
    if (!validChars.test(username)) {
      errors.push("Solo letras, números y guiones bajos")
    }

    return {
      isValid: errors.length === 0,
      errors: errors,
    }
  },
}

// Utilidades de UI
const UI = {
  showAlert: (message, type = "info", duration = 5000) => {
    const alertContainer = document.getElementById("alertContainer") || document.body

    const alert = document.createElement("div")
    alert.className = `alert ${type}`
    alert.innerHTML = `
            <span>${message}</span>
            <button onclick="this.parentElement.remove()" style="margin-left: auto; background: none; border: none; font-size: 1.2em; cursor: pointer;">&times;</button>
        `
    alert.style.display = "flex"
    alert.style.alignItems = "center"
    alert.style.justifyContent = "space-between"

    alertContainer.appendChild(alert)

    if (duration > 0) {
      setTimeout(() => {
        if (alert.parentElement) {
          alert.remove()
        }
      }, duration)
    }

    return alert
  },

  showModal: (title, content, actions = []) => {
    const overlay = document.getElementById("modalOverlay")
    const modalContent = document.getElementById("modalContent")

    if (!overlay || !modalContent) {
      console.error("Modal elements not found")
      return
    }

    const actionsHtml = actions
      .map(
        (action) =>
          `<button class="btn ${action.class || "secondary-btn"}" onclick="${action.onclick || ""}">${action.text}</button>`,
      )
      .join("")

    modalContent.innerHTML = `
            <div class="modal-header">
                <h3>${title}</h3>
                <button class="modal-close" onclick="UI.hideModal()">&times;</button>
            </div>
            <div class="modal-body">
                ${content}
            </div>
            ${actions.length > 0 ? `<div class="modal-footer">${actionsHtml}</div>` : ""}
        `

    overlay.classList.add("show")

    // Cerrar con Escape
    const handleEscape = (e) => {
      if (e.key === "Escape") {
        UI.hideModal()
        document.removeEventListener("keydown", handleEscape)
      }
    }
    document.addEventListener("keydown", handleEscape)

    // Cerrar al hacer clic fuera
    overlay.onclick = (e) => {
      if (e.target === overlay) {
        UI.hideModal()
      }
    }
  },

  hideModal: () => {
    const overlay = document.getElementById("modalOverlay")
    if (overlay) {
      overlay.classList.remove("show")
    }
  },

  setLoading: (element, loading = true) => {
    if (typeof element === "string") {
      element = document.getElementById(element)
    }

    if (!element) return

    if (loading) {
      element.disabled = true
      const loadingSpan = element.querySelector(".btn-loading")
      const textSpan = element.querySelector(".btn-text")

      if (loadingSpan && textSpan) {
        loadingSpan.style.display = "flex"
        textSpan.style.display = "none"
      } else {
        element.innerHTML = '<span class="btn-loading">Cargando...</span>'
      }
    } else {
      element.disabled = false
      const loadingSpan = element.querySelector(".btn-loading")
      const textSpan = element.querySelector(".btn-text")

      if (loadingSpan && textSpan) {
        loadingSpan.style.display = "none"
        textSpan.style.display = "inline"
      }
    }
  },

  updateTable: (tableId, data, columns) => {
    const table = document.getElementById(tableId)
    if (!table) return

    const tbody = table.querySelector("tbody")
    if (!tbody) return

    if (data.length === 0) {
      tbody.innerHTML = `<tr><td colspan="${columns.length}" class="text-center text-muted">No hay datos disponibles</td></tr>`
      return
    }

    tbody.innerHTML = data
      .map((row) => {
        const cells = columns
          .map((col) => {
            let value = row[col.key]
            if (col.format) {
              value = col.format(value, row)
            }
            return `<td>${value || "-"}</td>`
          })
          .join("")

        return `<tr>${cells}</tr>`
      })
      .join("")
  },
}

// Utilidades de formato
const Format = {
  riskLevel: (level) => {
    const levels = {
      low: { text: "Bajo", class: "badge info" },
      medium: { text: "Medio", class: "badge warning" },
      high: { text: "Alto", class: "badge error" },
      critical: { text: "Crítico", class: "badge error" },
    }

    const config = levels[level] || { text: level, class: "badge neutral" }
    return `<span class="${config.class}">${config.text}</span>`
  },

  status: (status) => {
    const statuses = {
      active: { text: "Activo", class: "badge success" },
      inactive: { text: "Inactivo", class: "badge neutral" },
      suspended: { text: "Suspendido", class: "badge error" },
      pending: { text: "Pendiente", class: "badge warning" },
      completed: { text: "Completado", class: "badge success" },
      failed: { text: "Fallido", class: "badge error" },
      expired: { text: "Expirado", class: "badge warning" },
      revoked: { text: "Revocado", class: "badge error" },
    }

    const config = statuses[status] || { text: status, class: "badge neutral" }
    return `<span class="${config.class}">${config.text}</span>`
  },

  boolean: (value) => {
    return value ? '<span class="badge success">Sí</span>' : '<span class="badge neutral">No</span>'
  },

  riskScore: (score) => {
    if (score === null || score === undefined) return "-"

    const numScore = Number.parseFloat(score)
    let className = "text-success"

    if (numScore >= 9.0) className = "text-error font-bold"
    else if (numScore >= 7.0) className = "text-error"
    else if (numScore >= 4.0) className = "text-warning"

    return `<span class="${className}">${numScore.toFixed(1)}</span>`
  },

  actions: (actions) => {
    return actions
      .map(
        (action) =>
          `<button class="btn ${action.class || "secondary-btn"} btn-sm" onclick="${action.onclick}" title="${action.title || ""}">${action.text}</button>`,
      )
      .join(" ")
  },
}

// Utilidades de red
const Http = {
  request: async (url, options = {}) => {
    const token = Storage.get("authToken")

    const defaultOptions = {
      headers: {
        "Content-Type": "application/json",
        ...(token && { Authorization: `Bearer ${token}` }),
      },
    }

    const finalOptions = {
      ...defaultOptions,
      ...options,
      headers: {
        ...defaultOptions.headers,
        ...options.headers,
      },
    }

    try {
      const response = await fetch(`${API_BASE_URL}${url}`, finalOptions)

      if (response.status === 401) {
        // Token expirado o inválido
        Storage.remove("authToken")
        Storage.remove("currentUser")
        window.location.href = "/"
        return
      }

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }

      return data
    } catch (error) {
      console.error("HTTP Request Error:", error)
      throw error
    }
  },

  get: (url) => Http.request(url),

  post: (url, data) =>
    Http.request(url, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  put: (url, data) =>
    Http.request(url, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  delete: (url) =>
    Http.request(url, {
      method: "DELETE",
    }),
}

// Utilidades de debounce
const debounce = (func, wait) => {
  let timeout
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout)
      func(...args)
    }
    clearTimeout(timeout)
    timeout = setTimeout(later, wait)
  }
}

// Exportar utilidades globalmente
window.Storage = Storage
window.DateUtils = DateUtils
window.Validation = Validation
window.UI = UI
window.Format = Format
window.Http = Http
window.debounce = debounce
window.API_BASE_URL = API_BASE_URL

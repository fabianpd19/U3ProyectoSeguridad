// Sistema de utilidades y validaciones
window.Validation = {
  email: (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },

  username: (username) => {
    const errors = [];
    let isValid = true;

    if (!username) {
      errors.push("El usuario es requerido");
      isValid = false;
    } else {
      if (username.length < 3) {
        errors.push("mínimo 3 caracteres");
        isValid = false;
      }
      if (username.length > 30) {
        errors.push("máximo 30 caracteres");
        isValid = false;
      }
      if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
        errors.push("solo letras, números, puntos, guiones y guiones bajos");
        isValid = false;
      }
      if (/^[._-]/.test(username) || /[._-]$/.test(username)) {
        errors.push(
          "no puede empezar o terminar con puntos, guiones o guiones bajos"
        );
        isValid = false;
      }
    }

    return { isValid, errors };
  },

  password: (password) => {
    const errors = [];
    let isValid = true;
    let strength = "muy débil";

    if (!password) {
      errors.push("La contraseña es requerida");
      return { isValid: false, errors, strength };
    }

    // Requisitos mínimos
    if (password.length < 8) {
      errors.push("mínimo 8 caracteres");
      isValid = false;
    }

    if (!/[a-z]/.test(password)) {
      errors.push("al menos una letra minúscula");
      isValid = false;
    }

    if (!/[A-Z]/.test(password)) {
      errors.push("al menos una letra mayúscula");
      isValid = false;
    }

    if (!/\d/.test(password)) {
      errors.push("al menos un número");
      isValid = false;
    }

    // Cálculo de fortaleza
    let score = 0;

    // Longitud
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    // Complejidad
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 1;

    // Diversidad
    const uniqueChars = new Set(password.split("")).size;
    if (uniqueChars >= password.length * 0.7) score += 1;

    // Patrones comunes (penalización)
    if (/(.)\1{2,}/.test(password)) score -= 1; // Caracteres repetidos
    if (/123|234|345|456|567|678|789|890|abc|bcd|cde|def/i.test(password))
      score -= 1; // Secuencias
    if (/password|123456|qwerty|admin|user|login/i.test(password)) score -= 2; // Palabras comunes

    // Asignar nivel de fortaleza
    if (score <= 2) {
      strength = "muy débil";
    } else if (score <= 4) {
      strength = "débil";
    } else if (score <= 6) {
      strength = "media";
    } else if (score <= 8) {
      strength = "fuerte";
    } else {
      strength = "muy fuerte";
    }

    return { isValid, errors, strength };
  },

  captcha: (userInput, expectedResult) => {
    if (!userInput || !expectedResult) return false;
    return userInput.toString().trim() === expectedResult.toString().trim();
  },
};

// Sistema de utilidades de UI mejorado
window.UIUtils = {
  debounce: (func, wait) => {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  },

  formatDate: (date) => {
    return new Intl.DateTimeFormat("es-ES", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(date));
  },

  sanitizeInput: (input) => {
    if (typeof input !== "string") return input;
    return input.replace(/[<>&"]/g, (char) => {
      const entities = {
        "<": "&lt;",
        ">": "&gt;",
        "&": "&amp;",
        '"': "&quot;",
      };
      return entities[char];
    });
  },

  copyToClipboard: async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      // Fallback para navegadores que no soportan clipboard API
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.left = "-999999px";
      textArea.style.top = "-999999px";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();

      try {
        document.execCommand("copy");
        textArea.remove();
        return true;
      } catch (err) {
        textArea.remove();
        return false;
      }
    }
  },
};

// Sistema de eventos personalizado
window.EventManager = {
  events: {},

  on: (event, callback) => {
    if (!this.events[event]) {
      this.events[event] = [];
    }
    this.events[event].push(callback);
  },

  emit: (event, data) => {
    if (this.events[event]) {
      this.events[event].forEach((callback) => callback(data));
    }
  },

  off: (event, callback) => {
    if (this.events[event]) {
      this.events[event] = this.events[event].filter((cb) => cb !== callback);
    }
  },
};

// Detección de capacidades del navegador
window.BrowserCapabilities = {
  hasLocalStorage: () => {
    try {
      return "localStorage" in window && window["localStorage"] !== null;
    } catch (e) {
      return false;
    }
  },

  hasSessionStorage: () => {
    try {
      return "sessionStorage" in window && window["sessionStorage"] !== null;
    } catch (e) {
      return false;
    }
  },

  hasWebCrypto: () => {
    return "crypto" in window && "subtle" in window.crypto;
  },

  hasNotificationSupport: () => {
    return "Notification" in window;
  },

  hasFileAPI: () => {
    return window.File && window.FileReader && window.FileList && window.Blob;
  },
};

// Log centralizado con niveles
window.Logger = {
  levels: {
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3,
  },

  currentLevel: 2, // INFO por defecto

  log: (level, message, data = null) => {
    if (level <= this.currentLevel) {
      const timestamp = new Date().toISOString();
      const levelNames = ["ERROR", "WARN", "INFO", "DEBUG"];
      const levelName = levelNames[level];

      const logMessage = `[${timestamp}] ${levelName}: ${message}`;

      if (level === 0) {
        console.error(logMessage, data);
      } else if (level === 1) {
        console.warn(logMessage, data);
      } else {
        console.log(logMessage, data);
      }
    }
  },

  error: (message, data) => window.Logger.log(0, message, data),
  warn: (message, data) => window.Logger.log(1, message, data),
  info: (message, data) => window.Logger.log(2, message, data),
  debug: (message, data) => window.Logger.log(3, message, data),

  setLevel: (level) => {
    if (typeof level === "string") {
      window.Logger.currentLevel =
        window.Logger.levels[level.toUpperCase()] || 2;
    } else {
      window.Logger.currentLevel = level;
    }
  },
};

// Sistema de configuración global
window.Config = {
  // Configuraciones por defecto
  defaults: {
    apiTimeout: 10000,
    retryAttempts: 3,
    debounceDelay: 300,
    alertDuration: 5000,
    sessionWarningTime: 5 * 60 * 1000, // 5 minutos antes de expirar
    passwordMinLength: 8,
    usernameMinLength: 3,
    maxFileSize: 5 * 1024 * 1024, // 5MB
  },

  get: (key) => {
    return window.Config.defaults[key];
  },

  set: (key, value) => {
    window.Config.defaults[key] = value;
  },
};

// Utilidades de red y API
window.NetworkUtils = {
  isOnline: () => navigator.onLine,

  checkConnection: async () => {
    try {
      await fetch(`${window.API_BASE_URL}/health`, {
        method: "HEAD",
        timeout: 5000,
      });
      return true;
    } catch {
      return false;
    }
  },

  retryRequest: async (requestFn, maxRetries = 3, delay = 1000) => {
    let lastError;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await requestFn();
      } catch (error) {
        lastError = error;

        if (attempt === maxRetries) {
          throw lastError;
        }

        // Esperar antes del siguiente intento (backoff exponencial)
        await new Promise((resolve) =>
          setTimeout(resolve, delay * Math.pow(2, attempt - 1))
        );
      }
    }
  },
};

// Sistema de caché simple
window.CacheManager = {
  cache: new Map(),

  get: (key) => {
    const item = window.CacheManager.cache.get(key);
    if (!item) return null;

    if (Date.now() > item.expiry) {
      window.CacheManager.cache.delete(key);
      return null;
    }

    return item.data;
  },

  set: (key, data, ttlMs = 300000) => {
    // 5 minutos por defecto
    const expiry = Date.now() + ttlMs;
    window.CacheManager.cache.set(key, { data, expiry });
  },

  delete: (key) => {
    window.CacheManager.cache.delete(key);
  },

  clear: () => {
    window.CacheManager.cache.clear();
  },

  cleanup: () => {
    const now = Date.now();
    for (const [key, item] of window.CacheManager.cache.entries()) {
      if (now > item.expiry) {
        window.CacheManager.cache.delete(key);
      }
    }
  },
};

// Limpieza automática de caché cada 5 minutos
setInterval(() => {
  window.CacheManager.cleanup();
}, 5 * 60 * 1000);

// Detección de estado de conexión
window.addEventListener("online", () => {
  window.EventManager.emit("connection:online");
  window.Logger.info("Conexión restaurada");
});

window.addEventListener("offline", () => {
  window.EventManager.emit("connection:offline");
  window.Logger.warn("Conexión perdida");
});

// Inicialización de utilidades
document.addEventListener("DOMContentLoaded", () => {
  // Configurar nivel de log basado en el entorno
  if (
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1"
  ) {
    window.Logger.setLevel("DEBUG");
  } else {
    window.Logger.setLevel("INFO");
  }

  window.Logger.info("Utilidades cargadas correctamente");

  // Verificar capacidades del navegador
  if (!window.BrowserCapabilities.hasLocalStorage()) {
    console.warn("LocalStorage no está disponible");
  }

  if (!window.BrowserCapabilities.hasWebCrypto()) {
    console.warn("Web Crypto API no está disponible");
  }
});

// Dashboard dinámico que consume las APIs del backend

const Auth = require("./auth"); // Declare Auth variable
const UI = require("./ui"); // Declare UI variable
const Http = require("./http"); // Declare Http variable
const DateUtils = require("./dateUtils"); // Declare DateUtils variable
const Format = require("./format"); // Declare Format variable

class Dashboard {
  constructor() {
    this.refreshInterval = null;
    this.charts = {};
    this.init();
  }

  async init() {
    if (!Auth.requireAuth()) return;

    await this.loadDashboardData();
    this.setupEventListeners();
    this.startAutoRefresh();
  }

  async loadDashboardData() {
    try {
      UI.setLoading("dashboardContent", true);

      // Cargar datos en paralelo
      const [
        securityMetrics,
        recentAlerts,
        vulnerabilities,
        userActivity,
        systemStatus,
      ] = await Promise.all([
        Http.get("/security/metrics"),
        Http.get("/security/alerts?limit=10"),
        Http.get("/vulnerabilities?status=open&limit=5"),
        Http.get("/security/activity?limit=10"),
        Http.get("/security/status"),
      ]);

      this.updateSecurityMetrics(securityMetrics);
      this.updateRecentAlerts(recentAlerts);
      this.updateVulnerabilities(vulnerabilities);
      this.updateUserActivity(userActivity);
      this.updateSystemStatus(systemStatus);
      this.updateCharts(securityMetrics);
    } catch (error) {
      console.error("Error loading dashboard data:", error);
      UI.showAlert("Error cargando datos del dashboard", "error");
    } finally {
      UI.setLoading("dashboardContent", false);
    }
  }

  updateSecurityMetrics(data) {
    // Actualizar métricas principales
    document.getElementById("totalUsers").textContent = data.totalUsers || 0;
    document.getElementById("activeThreats").textContent =
      data.activeThreats || 0;
    document.getElementById("riskScore").textContent = data.riskScore
      ? data.riskScore.toFixed(1)
      : "0.0";
    document.getElementById("systemHealth").textContent =
      data.systemHealth || "Unknown";

    // Actualizar indicadores de riesgo
    const riskElement = document.getElementById("riskScore");
    if (riskElement) {
      const score = Number.parseFloat(data.riskScore || 0);
      riskElement.className =
        score >= 7
          ? "metric-value high-risk"
          : score >= 4
          ? "metric-value medium-risk"
          : "metric-value low-risk";
    }

    // Actualizar estado del sistema
    const healthElement = document.getElementById("systemHealth");
    if (healthElement) {
      healthElement.className =
        data.systemHealth === "Healthy"
          ? "metric-value healthy"
          : data.systemHealth === "Warning"
          ? "metric-value warning"
          : "metric-value critical";
    }
  }

  updateRecentAlerts(alerts) {
    const container = document.getElementById("recentAlerts");
    if (!container) return;

    if (!alerts || alerts.length === 0) {
      container.innerHTML =
        '<p class="text-muted">No hay alertas recientes</p>';
      return;
    }

    container.innerHTML = alerts
      .map(
        (alert) => `
      <div class="alert-item ${alert.severity}">
        <div class="alert-header">
          <span class="alert-title">${alert.title}</span>
          <span class="alert-time">${DateUtils.formatRelativeTime(
            alert.created_at
          )}</span>
        </div>
        <div class="alert-description">${alert.description}</div>
        <div class="alert-actions">
          <button class="btn btn-sm secondary-btn" onclick="Dashboard.viewAlert('${
            alert.id
          }')">Ver</button>
          ${
            alert.status === "open"
              ? `<button class="btn btn-sm primary-btn" onclick="Dashboard.resolveAlert('${alert.id}')">Resolver</button>`
              : ""
          }
        </div>
      </div>
    `
      )
      .join("");
  }

  updateVulnerabilities(vulnerabilities) {
    const container = document.getElementById("vulnerabilitiesList");
    if (!container) return;

    if (!vulnerabilities || vulnerabilities.length === 0) {
      container.innerHTML =
        '<p class="text-muted">No hay vulnerabilidades abiertas</p>';
      return;
    }

    container.innerHTML = vulnerabilities
      .map(
        (vuln) => `
      <div class="vulnerability-item">
        <div class="vuln-header">
          <span class="vuln-title">${vuln.title}</span>
          ${Format.riskLevel(vuln.severity)}
        </div>
        <div class="vuln-description">${vuln.description}</div>
        <div class="vuln-meta">
          <span>Detectado: ${DateUtils.formatRelativeTime(
            vuln.detected_at
          )}</span>
          <span>CVSS: ${vuln.cvss_score || "N/A"}</span>
        </div>
        <div class="vuln-actions">
          <button class="btn btn-sm secondary-btn" onclick="Dashboard.viewVulnerability('${
            vuln.id
          }')">Detalles</button>
          <button class="btn btn-sm primary-btn" onclick="Dashboard.fixVulnerability('${
            vuln.id
          }')">Corregir</button>
        </div>
      </div>
    `
      )
      .join("");
  }

  updateUserActivity(activities) {
    const container = document.getElementById("userActivity");
    if (!container) return;

    if (!activities || activities.length === 0) {
      container.innerHTML =
        '<p class="text-muted">No hay actividad reciente</p>';
      return;
    }

    container.innerHTML = activities
      .map(
        (activity) => `
      <div class="activity-item">
        <div class="activity-icon ${activity.type}"></div>
        <div class="activity-content">
          <div class="activity-description">${activity.description}</div>
          <div class="activity-meta">
            <span>${activity.username}</span>
            <span>${DateUtils.formatRelativeTime(activity.timestamp)}</span>
            <span>IP: ${activity.ip_address}</span>
          </div>
        </div>
      </div>
    `
      )
      .join("");
  }

  updateSystemStatus(status) {
    const container = document.getElementById("systemStatus");
    if (!container) return;

    const services = status.services || [];

    container.innerHTML = services
      .map(
        (service) => `
      <div class="service-item">
        <div class="service-name">${service.name}</div>
        <div class="service-status ${service.status}">${service.status}</div>
        <div class="service-uptime">${service.uptime || "N/A"}</div>
      </div>
    `
      )
      .join("");
  }

  updateCharts(data) {
    // Actualizar gráfico de amenazas por tiempo
    this.updateThreatChart(data.threatTrends || []);

    // Actualizar gráfico de distribución de riesgos
    this.updateRiskChart(data.riskDistribution || {});
  }

  updateThreatChart(trends) {
    const canvas = document.getElementById("threatChart");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");

    // Limpiar canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Dibujar gráfico simple de líneas
    if (trends.length > 0) {
      const maxValue = Math.max(...trends.map((t) => t.count));
      const stepX = canvas.width / (trends.length - 1);
      const stepY = canvas.height / maxValue;

      ctx.strokeStyle = "#e74c3c";
      ctx.lineWidth = 2;
      ctx.beginPath();

      trends.forEach((trend, index) => {
        const x = index * stepX;
        const y = canvas.height - trend.count * stepY;

        if (index === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      });

      ctx.stroke();
    }
  }

  updateRiskChart(distribution) {
    const canvas = document.getElementById("riskChart");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const total = Object.values(distribution).reduce(
      (sum, val) => sum + val,
      0
    );
    if (total === 0) return;

    const colors = {
      low: "#27ae60",
      medium: "#f39c12",
      high: "#e74c3c",
      critical: "#8e44ad",
    };

    let currentAngle = 0;
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 10;

    Object.entries(distribution).forEach(([level, count]) => {
      const sliceAngle = (count / total) * 2 * Math.PI;

      ctx.fillStyle = colors[level] || "#95a5a6";
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(
        centerX,
        centerY,
        radius,
        currentAngle,
        currentAngle + sliceAngle
      );
      ctx.closePath();
      ctx.fill();

      currentAngle += sliceAngle;
    });
  }

  setupEventListeners() {
    // Botón de actualizar
    const refreshBtn = document.getElementById("refreshDashboard");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => this.loadDashboardData());
    }

    // Filtros de tiempo
    const timeFilters = document.querySelectorAll(".time-filter");
    timeFilters.forEach((filter) => {
      filter.addEventListener("click", (e) => {
        timeFilters.forEach((f) => f.classList.remove("active"));
        e.target.classList.add("active");
        this.loadDashboardData();
      });
    });
  }

  startAutoRefresh() {
    // Actualizar cada 30 segundos
    this.refreshInterval = setInterval(() => {
      this.loadDashboardData();
    }, 30000);
  }

  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  // Métodos de acción
  static async viewAlert(alertId) {
    try {
      const alert = await Http.get(`/security/alerts/${alertId}`);

      UI.showModal(
        "Detalles de Alerta",
        `
        <div class="alert-details">
          <h4>${alert.title}</h4>
          <p><strong>Severidad:</strong> ${Format.riskLevel(alert.severity)}</p>
          <p><strong>Descripción:</strong> ${alert.description}</p>
          <p><strong>Fecha:</strong> ${DateUtils.formatDateTime(
            alert.created_at
          )}</p>
          <p><strong>Estado:</strong> ${Format.status(alert.status)}</p>
          ${
            alert.details
              ? `<div class="alert-raw-details"><pre>${JSON.stringify(
                  alert.details,
                  null,
                  2
                )}</pre></div>`
              : ""
          }
        </div>
      `,
        [
          { text: "Cerrar", class: "secondary-btn", onclick: "UI.hideModal()" },
          {
            text: "Resolver",
            class: "primary-btn",
            onclick: `Dashboard.resolveAlert('${alertId}')`,
          },
        ]
      );
    } catch (error) {
      UI.showAlert("Error cargando detalles de la alerta", "error");
    }
  }

  static async resolveAlert(alertId) {
    try {
      await Http.put(`/security/alerts/${alertId}`, { status: "resolved" });
      UI.showAlert("Alerta resuelta correctamente", "success");
      UI.hideModal();
      window.dashboard.loadDashboardData();
    } catch (error) {
      UI.showAlert("Error resolviendo la alerta", "error");
    }
  }

  static async viewVulnerability(vulnId) {
    try {
      const vuln = await Http.get(`/vulnerabilities/${vulnId}`);

      UI.showModal(
        "Detalles de Vulnerabilidad",
        `
        <div class="vuln-details">
          <h4>${vuln.title}</h4>
          <p><strong>Severidad:</strong> ${Format.riskLevel(vuln.severity)}</p>
          <p><strong>CVSS Score:</strong> ${vuln.cvss_score || "N/A"}</p>
          <p><strong>Descripción:</strong> ${vuln.description}</p>
          <p><strong>Detectado:</strong> ${DateUtils.formatDateTime(
            vuln.detected_at
          )}</p>
          <p><strong>Estado:</strong> ${Format.status(vuln.status)}</p>
          ${
            vuln.solution
              ? `<div class="vuln-solution"><h5>Solución:</h5><p>${vuln.solution}</p></div>`
              : ""
          }
        </div>
      `,
        [
          { text: "Cerrar", class: "secondary-btn", onclick: "UI.hideModal()" },
          {
            text: "Marcar como Corregida",
            class: "primary-btn",
            onclick: `Dashboard.fixVulnerability('${vulnId}')`,
          },
        ]
      );
    } catch (error) {
      UI.showAlert("Error cargando detalles de la vulnerabilidad", "error");
    }
  }

  static async fixVulnerability(vulnId) {
    try {
      await Http.put(`/vulnerabilities/${vulnId}`, { status: "fixed" });
      UI.showAlert("Vulnerabilidad marcada como corregida", "success");
      UI.hideModal();
      window.dashboard.loadDashboardData();
    } catch (error) {
      UI.showAlert("Error actualizando la vulnerabilidad", "error");
    }
  }
}

// Inicializar dashboard cuando se carga la página
document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("dashboardContent")) {
    window.dashboard = new Dashboard();
  }
});

// Limpiar intervalos al salir de la página
window.addEventListener("beforeunload", () => {
  if (window.dashboard) {
    window.dashboard.stopAutoRefresh();
  }
});

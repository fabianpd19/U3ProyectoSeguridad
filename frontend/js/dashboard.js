// Dashboard funcional que consume las APIs reales del backend
class FunctionalDashboard {
  constructor() {
    this.refreshInterval = null;
    this.charts = {};
    this.currentSection = 'dashboard';
    this.autoRefreshTime = 60000; // 1 minuto
    
    this.elements = {
      // Métricas principales
      totalUsers: document.getElementById('totalUsers'),
      activeSessions: document.getElementById('activeSessions'),
      failedLogins: document.getElementById('failedLogins'),
      suspiciousActivities: document.getElementById('suspiciousActivities'),
      
      // Listas de contenido
      suspiciousIPs: document.getElementById('suspiciousIPs'),
      recentAlerts: document.getElementById('recentAlerts'),
      
      // Canvas para gráficos
      loginTrendsChart: document.getElementById('loginTrendsChart'),
      
      // Información de usuario
      currentUser: document.getElementById('currentUser'),
      userDisplayName: document.getElementById('userDisplayName'),
      
      // Botones de acción
      refreshBtn: document.getElementById('refreshBtn'),
      logoutBtn: document.getElementById('logoutBtn'),
      logoutLink: document.getElementById('logoutLink')
    };
  }

  // Inicialización del dashboard
  async init() {
    if (!window.AuthManager?.requireAuth()) {
      return;
    }

    this.setupEventListeners();
    this.setupNavigation();
    this.setUserInfo();
    await this.loadDashboardData();
    this.startAutoRefresh();
    
    window.Logger?.info('Dashboard funcional inicializado');
  }

  // Configurar event listeners
  setupEventListeners() {
    // Botón de actualizar
    if (this.elements.refreshBtn) {
      this.elements.refreshBtn.addEventListener('click', () => this.loadDashboardData());
    }

    // Botones de logout
    if (this.elements.logoutBtn) {
      this.elements.logoutBtn.addEventListener('click', () => this.logout());
    }
    if (this.elements.logoutLink) {
      this.elements.logoutLink.addEventListener('click', (e) => {
        e.preventDefault();
        this.logout();
      });
    }

    // Menú desplegable de usuario
    const userMenuBtn = document.getElementById('userMenuBtn');
    const userDropdown = document.getElementById('userDropdown');
    if (userMenuBtn && userDropdown) {
      userMenuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        userDropdown.classList.toggle('show');
      });
      
      document.addEventListener('click', () => {
        userDropdown.classList.remove('show');
      });
    }

    // Configurar 2FA
    const setup2FABtn = document.getElementById('setup2FA');
    if (setup2FABtn) {
      setup2FABtn.addEventListener('click', (e) => {
        e.preventDefault();
        this.setup2FA();
      });
    }
  }

  // Configurar navegación entre secciones
  setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link[data-section]');
    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const section = link.getAttribute('data-section');
        this.showSection(section);
      });
    });
  }

  // Mostrar sección específica
  showSection(sectionName) {
    // Ocultar todas las secciones
    const sections = document.querySelectorAll('.content-section');
    sections.forEach(section => section.classList.remove('active'));
    
    // Mostrar la sección seleccionada
    const targetSection = document.getElementById(`${sectionName}-section`);
    if (targetSection) {
      targetSection.classList.add('active');
    }

    // Actualizar navegación activa
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => item.classList.remove('active'));
    
    const activeNavItem = document.querySelector(`[data-section="${sectionName}"]`).closest('.nav-item');
    if (activeNavItem) {
      activeNavItem.classList.add('active');
    }

    // Actualizar título de página
    const titles = {
      dashboard: 'Dashboard de Seguridad',
      users: 'Gestión de Usuarios',
      roles: 'Roles y Permisos',
      vulnerabilities: 'Análisis de Vulnerabilidades',
      certificates: 'Certificados Digitales',
      'security-logs': 'Logs de Seguridad',
      alerts: 'Configuración de Alertas'
    };

    const pageTitle = document.getElementById('pageTitle');
    if (pageTitle && titles[sectionName]) {
      pageTitle.textContent = titles[sectionName];
    }

    this.currentSection = sectionName;
    
    // Cargar datos específicos de la sección
    this.loadSectionData(sectionName);
  }

  // Cargar datos específicos de cada sección
  async loadSectionData(sectionName) {
    switch (sectionName) {
      case 'dashboard':
        await this.loadDashboardData();
        break;
      case 'vulnerabilities':
        await this.loadVulnerabilitiesData();
        break;
      case 'certificates':
        await this.loadCertificatesData();
        break;
      case 'security-logs':
        await this.loadSecurityLogsData();
        break;
      case 'alerts':
        await this.loadAlertsData();
        break;
    }
  }

  // Cargar datos principales del dashboard
  async loadDashboardData() {
    try {
      this.setRefreshButtonLoading(true);
      
      const data = await window.API.security.getDashboard();
      
      this.updateMetrics(data.metrics);
      this.updateRecentAlerts(data.recentAlerts);
      this.updateSuspiciousIPs(data.trends.suspiciousIPs);
      this.updateLoginChart(data.trends.loginTrends);
      
      window.Logger?.info('Datos del dashboard actualizados');
      
    } catch (error) {
      window.Logger?.error('Error cargando datos del dashboard:', error);
      window.UI?.showAlert('Error cargando datos del dashboard', 'error');
    } finally {
      this.setRefreshButtonLoading(false);
    }
  }

  // Actualizar métricas principales
  updateMetrics(metrics) {
    if (!metrics) return;

    this.safeUpdateElement(this.elements.totalUsers, metrics.totalUsers ?? '0');
    this.safeUpdateElement(this.elements.activeSessions, metrics.activeSessions ?? '0');
    this.safeUpdateElement(this.elements.failedLogins, metrics.failedLogins24h ?? '0');
    this.safeUpdateElement(this.elements.suspiciousActivities, metrics.suspiciousActivities7d ?? '0');
  }

  // Actualizar alertas recientes
  updateRecentAlerts(alerts) {
    if (!this.elements.recentAlerts) return;

    this.elements.recentAlerts.innerHTML = '';

    if (!alerts || alerts.length === 0) {
      this.elements.recentAlerts.innerHTML = '<div class="no-data">No hay alertas críticas recientes</div>';
      return;
    }

    alerts.forEach(alert => {
      const alertElement = document.createElement('div');
      alertElement.className = 'alert-item critical';
      
      const details = alert.details || {};
      const message = details.message || 'Detalle no disponible';
      
      alertElement.innerHTML = `
        <p><strong>${window.UIUtils?.sanitizeInput(alert.action)}</strong>: ${window.UIUtils?.sanitizeInput(message)}</p>
        <small>${window.UIUtils?.formatDate(alert.created_at)} - IP: ${alert.ip_address}</small>
      `;
      
      this.elements.recentAlerts.appendChild(alertElement);
    });
  }

  // Actualizar IPs sospechosas
  updateSuspiciousIPs(ips) {
    if (!this.elements.suspiciousIPs) return;

    this.elements.suspiciousIPs.innerHTML = '';

    if (!ips || ips.length === 0) {
      this.elements.suspiciousIPs.innerHTML = '<div class="no-data">No se han detectado IPs sospechosas</div>';
      return;
    }

    ips.forEach(ip => {
      const ipElement = document.createElement('div');
      ipElement.className = 'ip-item';
      
      ipElement.innerHTML = `
        <div class="ip-info">
          <span class="ip-address">${ip.ip_address}</span>
          <span class="ip-count">${ip.incident_count} incidentes</span>
          <small>Último: ${window.UIUtils?.formatDate(ip.last_incident)}</small>
        </div>
        <button class="action-btn-sm" onclick="dashboard.blockIP('${ip.ip_address}')" title="Bloquear IP">
          🚫 Bloquear
        </button>
      `;
      
      this.elements.suspiciousIPs.appendChild(ipElement);
    });
  }

  // Actualizar gráfico de tendencias de login
  updateLoginChart(loginTrends) {
    if (!this.elements.loginTrendsChart || !loginTrends || !window.Chart) return;

    // Destruir gráfico anterior si existe
    if (this.charts.loginChart) {
      this.charts.loginChart.destroy();
    }

    if (loginTrends.length === 0) {
      const ctx = this.elements.loginTrendsChart.getContext('2d');
      ctx.clearRect(0, 0, this.elements.loginTrendsChart.width, this.elements.loginTrendsChart.height);
      ctx.font = '16px Arial';
      ctx.fillStyle = '#666';
      ctx.textAlign = 'center';
      ctx.fillText('Sin datos disponibles', this.elements.loginTrendsChart.width / 2, this.elements.loginTrendsChart.height / 2);
      return;
    }

    const labels = loginTrends.map(d => 
      new Date(d.date).toLocaleDateString('es-ES', {
        day: 'numeric',
        month: 'short'
      })
    );

    const successfulData = loginTrends.map(d => d.successful_logins || 0);
    const failedData = loginTrends.map(d => d.failed_logins || 0);

    this.charts.loginChart = new Chart(this.elements.loginTrendsChart.getContext('2d'), {
      type: 'line',
      data: {
        labels: labels.reverse(),
        datasets: [
          {
            label: 'Logins Exitosos',
            data: successfulData.reverse(),
            borderColor: 'rgba(75, 192, 192, 1)',
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            fill: true,
            tension: 0.3
          },
          {
            label: 'Logins Fallidos',
            data: failedData.reverse(),
            borderColor: 'rgba(255, 99, 132, 1)',
            backgroundColor: 'rgba(255, 99, 132, 0.2)',
            fill: true,
            tension: 0.3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true
          }
        },
        plugins: {
          legend: {
            position: 'top'
          }
        }
      }
    });
  }

  // Cargar datos de vulnerabilidades
  async loadVulnerabilitiesData() {
    try {
      const [scans, stats] = await Promise.all([
        window.API.vulnerabilities.getScans({ limit: 10 }),
        window.API.vulnerabilities.getStats()
      ]);

      this.updateVulnerabilityStats(stats);
      this.updateVulnerabilityTable(scans);
      
    } catch (error) {
      window.Logger?.error('Error cargando datos de vulnerabilidades:', error);
      window.UI?.showAlert('Error cargando vulnerabilidades', 'error');
    }
  }

  // Actualizar estadísticas de vulnerabilidades
  updateVulnerabilityStats(stats) {
    if (!stats) return;

    this.safeUpdateElement(document.getElementById('totalScans'), stats.overview?.totalScans ?? '0');
    this.safeUpdateElement(document.getElementById('criticalVulns'), stats.overview?.criticalVulnerabilities ?? '0');
    this.safeUpdateElement(document.getElementById('highRiskScans'), stats.overview?.highRiskScans ?? '0');
  }

  // Actualizar tabla de vulnerabilidades
  updateVulnerabilityTable(scans) {
    const table = document.getElementById('vulnerabilitiesTable');
    const tbody = table?.querySelector('tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!scans || scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="no-data">No hay escaneos disponibles</td></tr>';
      return;
    }

    scans.forEach(scan => {
      const row = document.createElement('tr');
      const vulnerabilities = Array.isArray(scan.vulnerabilities_found) ? scan.vulnerabilities_found : [];
      
      row.innerHTML = `
        <td>${window.UIUtils?.sanitizeInput(scan.scan_type)}</td>
        <td>${window.UIUtils?.sanitizeInput(scan.target_resource)}</td>
        <td>
          <span class="status-badge ${scan.status}">
            ${scan.status}
          </span>
        </td>
        <td>
          <span class="risk-score ${this.getRiskClass(scan.risk_score)}">
            ${scan.risk_score?.toFixed(1) || 'N/A'}
          </span>
        </td>
        <td>${vulnerabilities.length}</td>
        <td>${window.UIUtils?.formatDate(scan.scan_date)}</td>
        <td>
          <button class="action-btn" onclick="dashboard.viewScan(${scan.id})">Ver</button>
        </td>
      `;
      
      tbody.appendChild(row);
    });
  }

  // Cargar datos de certificados
  async loadCertificatesData() {
    try {
      const certificates = await window.API.certificates.getAll({ limit: 10 });
      this.updateCertificatesTable(certificates);
      
    } catch (error) {
      window.Logger?.error('Error cargando certificados:', error);
      window.UI?.showAlert('Error cargando certificados', 'error');
    }
  }

  // Actualizar tabla de certificados
  updateCertificatesTable(certificates) {
    const table = document.getElementById('certificatesTable');
    const tbody = table?.querySelector('tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!certificates || certificates.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="no-data">No hay certificados disponibles</td></tr>';
      return;
    }

    certificates.forEach(cert => {
      const row = document.createElement('tr');
      
      row.innerHTML = `
        <td>${window.UIUtils?.sanitizeInput(cert.serial_number)}</td>
        <td>
          <span class="status-badge ${cert.status}">
            ${cert.status}
          </span>
        </td>
        <td>${window.UIUtils?.formatDate(cert.issued_at)}</td>
        <td>${window.UIUtils?.formatDate(cert.expires_at)}</td>
        <td>
          <button class="action-btn" onclick="dashboard.viewCertificate(${cert.id})">Ver</button>
          ${cert.status === 'active' ? `<button class="action-btn danger" onclick="dashboard.revokeCertificate(${cert.id})">Revocar</button>` : ''}
        </td>
      `;
      
      tbody.appendChild(row);
    });
  }

  // Cargar logs de seguridad
  async loadSecurityLogsData() {
    try {
      const response = await window.API.security.getLogs({ limit: 20 });
      this.updateSecurityLogsTable(response.logs);
      
    } catch (error) {
      window.Logger?.error('Error cargando logs de seguridad:', error);
      window.UI?.showAlert('Error cargando logs', 'error');
    }
  }

  // Actualizar tabla de logs de seguridad
  updateSecurityLogsTable(logs) {
    const table = document.getElementById('securityLogsTable');
    const tbody = table?.querySelector('tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!logs || logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="no-data">No hay logs disponibles</td></tr>';
      return;
    }

    logs.forEach(log => {
      const row = document.createElement('tr');
      
      row.innerHTML = `
        <td>${window.UIUtils?.formatDate(log.created_at)}</td>
        <td>${window.UIUtils?.sanitizeInput(log.username || 'Sistema')}</td>
        <td>${window.UIUtils?.sanitizeInput(log.action)}</td>
        <td>${window.UIUtils?.sanitizeInput(log.resource || 'N/A')}</td>
        <td>${window.UIUtils?.sanitizeInput(log.ip_address)}</td>
        <td>
          <span class="risk-level ${log.risk_level}">
            ${log.risk_level}
          </span>
        </td>
        <td>
          <span class="status-badge ${log.success ? 'success' : 'failed'}">
            ${log.success ? 'Éxito' : 'Fallido'}
          </span>
        </td>
      `;
      
      tbody.appendChild(row);
    });
  }

  // Cargar configuración de alertas
  async loadAlertsData() {
    try {
      const alerts = await window.API.security.getAlerts();
      this.updateAlertsContainer(alerts);
      
    } catch (error) {
      window.Logger?.error('Error cargando alertas:', error);
      window.UI?.showAlert('Error cargando alertas', 'error');
    }
  }

  // Actualizar contenedor de alertas
  updateAlertsContainer(alerts) {
    const container = document.getElementById('alertsContainer');
    if (!container) return;

    container.innerHTML = '';

    if (!alerts || alerts.length === 0) {
      container.innerHTML = '<div class="no-data">No hay alertas configuradas</div>';
      return;
    }

    alerts.forEach(alert => {
      const alertElement = document.createElement('div');
      alertElement.className = 'alert-config-item';
      
      alertElement.innerHTML = `
        <div class="alert-config-header">
          <h4>${window.UIUtils?.sanitizeInput(alert.alert_type)}</h4>
          <span class="status-badge ${alert.is_active ? 'active' : 'inactive'}">
            ${alert.is_active ? 'Activa' : 'Inactiva'}
          </span>
        </div>
        <div class="alert-config-details">
          <p>Configurado por: ${window.UIUtils?.sanitizeInput(alert.created_by_username)}</p>
          <p>Fecha: ${window.UIUtils?.formatDate(alert.created_at)}</p>
        </div>
        <div class="alert-config-actions">
          <button class="action-btn" onclick="dashboard.editAlert(${alert.id})">Editar</button>
          <button class="action-btn ${alert.is_active ? 'danger' : 'success'}" onclick="dashboard.toggleAlert(${alert.id})">
            ${alert.is_active ? 'Desactivar' : 'Activar'}
          </button>
        </div>
      `;
      
      container.appendChild(alertElement);
    });
  }

  // Métodos de acción
  async blockIP(ipAddress) {
    // Esta funcionalidad requeriría implementar el endpoint en el backend
    window.UI?.showAlert(`Funcionalidad para bloquear IP ${ipAddress} no implementada`, 'info');
  }

  async viewScan(scanId) {
    try {
      const scan = await window.API.vulnerabilities.getScan(scanId);
      this.showScanModal(scan);
    } catch (error) {
      window.UI?.showAlert('Error obteniendo detalles del escaneo', 'error');
    }
  }

  showScanModal(scan) {
    const vulnerabilities = Array.isArray(scan.vulnerabilities_found) ? scan.vulnerabilities_found : [];
    
    const modalContent = `
      <h3>Detalles del Escaneo</h3>
      <div class="scan-details">
        <p><strong>Tipo:</strong> ${window.UIUtils?.sanitizeInput(scan.scan_type)}</p>
        <p><strong>Recurso:</strong> ${window.UIUtils?.sanitizeInput(scan.target_resource)}</p>
        <p><strong>Estado:</strong> ${scan.status}</p>
        <p><strong>Puntuación de riesgo:</strong> ${scan.risk_score?.toFixed(1) || 'N/A'}</p>
        <p><strong>Fecha:</strong> ${window.UIUtils?.formatDate(scan.scan_date)}</p>
        ${scan.recommendations ? `<p><strong>Recomendaciones:</strong> ${window.UIUtils?.sanitizeInput(scan.recommendations)}</p>` : ''}
        
        ${vulnerabilities.length > 0 ? `
          <h4>Vulnerabilidades encontradas (${vulnerabilities.length}):</h4>
          <ul>
            ${vulnerabilities.map(v => `<li>${window.UIUtils?.sanitizeInput(v.description || v.type || 'Vulnerabilidad')}</li>`).join('')}
          </ul>
        ` : '<p>No se encontraron vulnerabilidades</p>'}
      </div>
    `;

    this.showModal(modalContent);
  }

  showModal(content) {
    const modalOverlay = document.getElementById('modalOverlay');
    const modalContent = document.getElementById('modalContent');
    
    if (modalOverlay && modalContent) {
      modalContent.innerHTML = content;
      modalOverlay.style.display = 'flex';
      
      // Cerrar modal al hacer clic fuera
      modalOverlay.onclick = (e) => {
        if (e.target === modalOverlay) {
          modalOverlay.style.display = 'none';
        }
      };
    }
  }

  // Métodos de utilidad
  safeUpdateElement(element, value) {
    if (element && value !== undefined) {
      element.textContent = value.toString();
    }
  }

  setRefreshButtonLoading(isLoading) {
    if (!this.elements.refreshBtn) return;
    
    if (isLoading) {
      this.elements.refreshBtn.disabled = true;
      this.elements.refreshBtn.textContent = 'Cargando...';
    } else {
      this.elements.refreshBtn.disabled = false;
      this.elements.refreshBtn.textContent = '🔄 Actualizar';
    }
  }

  getRiskClass(riskScore) {
    if (!riskScore) return 'unknown';
    if (riskScore >= 9) return 'critical';
    if (riskScore >= 7) return 'high';
    if (riskScore >= 4) return 'medium';
    return 'low';
  }

  setUserInfo() {
    try {
      const user = window.AuthManager?.getCurrentUser();
      if (user && user.username) {
        const sanitizedUsername = window.UIUtils?.sanitizeInput(user.username);
        if (this.elements.currentUser) {
          this.elements.currentUser.textContent = sanitizedUsername;
        }
        if (this.elements.userDisplayName) {
          this.elements.userDisplayName.textContent = sanitizedUsername;
        }
      }
    } catch (error) {
      window.Logger?.error('Error al mostrar información de usuario:', error);
    }
  }

  logout() {
    if (window.AuthManager) {
      window.AuthManager.logout();
    } else {
      // Fallback manual
      window.Storage?.remove('authToken');
      window.Storage?.remove('currentUser');
      window.location.href = '/index.html';
    }
  }

  async setup2FA() {
    try {
      const response = await window.AuthManager?.setup2FA();
      if (response) {
        const modalContent = `
          <h3>Configurar Autenticación de Dos Factores</h3>
          <div class="2fa-setup">
            <p>Escanea este código QR con tu aplicación de autenticación:</p>
            <div class="qr-code">
              <img src="${response.qrCode}" alt="QR Code para 2FA" />
            </div>
            <p>O ingresa este código manualmente:</p>
            <code>${response.secret}</code>
            <div class="form-group">
              <label>Código de verificación:</label>
              <input type="text" id="verify2FACode" placeholder="Ingresa el código de 6 dígitos" />
            </div>
            <div class="modal-actions">
              <button class="btn secondary" onclick="document.getElementById('modalOverlay').style.display='none'">Cancelar</button>
              <button class="btn primary" onclick="dashboard.verify2FA()">Verificar</button>
            </div>
          </div>
        `;
        this.showModal(modalContent);
      }
    } catch (error) {
      window.UI?.showAlert('Error configurando 2FA: ' + error.message, 'error');
    }
  }

  async verify2FA() {
    const code = document.getElementById('verify2FACode')?.value;
    if (!code) {
      window.UI?.showAlert('Por favor ingresa el código de verificación', 'error');
      return;
    }

    try {
      await window.AuthManager?.verify2FA(code);
      window.UI?.showAlert('2FA configurado exitosamente', 'success');
      document.getElementById('modalOverlay').style.display = 'none';
    } catch (error) {
      window.UI?.showAlert('Error verificando 2FA: ' + error.message, 'error');
    }
  }

  // Iniciar escaneo de vulnerabilidades
  async startVulnerabilityScan() {
    try {
      const modalContent = `
        <h3>Nuevo Escaneo de Vulnerabilidades</h3>
        <div class="scan-form">
          <div class="form-group">
            <label>Tipo de escaneo:</label>
            <select id="scanType">
              <option value="port_scan">Escaneo de Puertos</option>
              <option value="web_scan">Escaneo Web</option>
              <option value="network_scan">Escaneo de Red</option>
              <option value="system_scan">Escaneo de Sistema</option>
            </select>
          </div>
          <div class="form-group">
            <label>Recurso objetivo:</label>
            <input type="text" id="targetResource" placeholder="ej: 192.168.1.1, example.com" />
          </div>
          <div class="modal-actions">
            <button class="btn secondary" onclick="document.getElementById('modalOverlay').style.display='none'">Cancelar</button>
            <button class="btn primary" onclick="dashboard.executeVulnerabilityScan()">Iniciar Escaneo</button>
          </div>
        </div>
      `;
      this.showModal(modalContent);
    } catch (error) {
      window.UI?.showAlert('Error abriendo formulario de escaneo', 'error');
    }
  }

  async executeVulnerabilityScan() {
    const scanType = document.getElementById('scanType')?.value;
    const targetResource = document.getElementById('targetResource')?.value;

    if (!scanType || !targetResource) {
      window.UI?.showAlert('Por favor completa todos los campos', 'error');
      return;
    }

    try {
      const response = await window.API.vulnerabilities.startScan({
        scanType,
        targetResource
      });
      
      window.UI?.showAlert(`Escaneo iniciado. ID: ${response.scanId}`, 'success');
      document.getElementById('modalOverlay').style.display = 'none';
      
      // Recargar datos de vulnerabilidades
      if (this.currentSection === 'vulnerabilities') {
        setTimeout(() => this.loadVulnerabilitiesData(), 2000);
      }
    } catch (error) {
      window.UI?.showAlert('Error iniciando escaneo: ' + error.message, 'error');
    }
  }

  // Generar certificado digital
  async generateCertificate() {
    try {
      const modalContent = `
        <h3>Generar Certificado Digital</h3>
        <div class="cert-form">
          <div class="form-group">
            <label>Tipo de certificado:</label>
            <select id="certType">
              <option value="self_signed">Auto-firmado</option>
              <option value="client_auth">Autenticación de Cliente</option>
              <option value="server_auth">Autenticación de Servidor</option>
            </select>
          </div>
          <div class="form-group">
            <label>Nombre común (CN):</label>
            <input type="text" id="commonName" placeholder="ej: usuario@ejemplo.com, ejemplo.com" />
          </div>
          <div class="form-group">
            <label>Duración (días):</label>
            <input type="number" id="validityDays" value="365" min="1" max="3650" />
          </div>
          <div class="modal-actions">
            <button class="btn secondary" onclick="document.getElementById('modalOverlay').style.display='none'">Cancelar</button>
            <button class="btn primary" onclick="dashboard.executeCertificateGeneration()">Generar</button>
          </div>
        </div>
      `;
      this.showModal(modalContent);
    } catch (error) {
      window.UI?.showAlert('Error abriendo formulario de certificado', 'error');
    }
  }

  async executeCertificateGeneration() {
    const certType = document.getElementById('certType')?.value;
    const commonName = document.getElementById('commonName')?.value;
    const validityDays = document.getElementById('validityDays')?.value;

    if (!certType || !commonName || !validityDays) {
      window.UI?.showAlert('Por favor completa todos los campos', 'error');
      return;
    }

    try {
      const response = await window.API.certificates.create({
        type: certType,
        commonName,
        validityDays: parseInt(validityDays)
      });
      
      window.UI?.showAlert('Certificado generado exitosamente', 'success');
      document.getElementById('modalOverlay').style.display = 'none';
      
      // Recargar datos de certificados
      if (this.currentSection === 'certificates') {
        setTimeout(() => this.loadCertificatesData(), 1000);
      }
    } catch (error) {
      window.UI?.showAlert('Error generando certificado: ' + error.message, 'error');
    }
  }

  // Configurar nueva alerta
  async configureAlert() {
    try {
      const modalContent = `
        <h3>Configurar Nueva Alerta</h3>
        <div class="alert-form">
          <div class="form-group">
            <label>Tipo de alerta:</label>
            <select id="alertType">
              <option value="failed_login_threshold">Intentos de login fallidos</option>
              <option value="suspicious_ip">IP sospechosa</option>
              <option value="high_risk_activity">Actividad de alto riesgo</option>
              <option value="vulnerability_detected">Vulnerabilidad detectada</option>
            </select>
          </div>
          <div class="form-group">
            <label>Umbral:</label>
            <input type="number" id="alertThreshold" placeholder="ej: 5" min="1" />
          </div>
          <div class="form-group">
            <label>Período (minutos):</label>
            <input type="number" id="alertPeriod" value="60" min="1" />
          </div>
          <div class="form-group">
            <label>Acción:</label>
            <select id="alertAction">
              <option value="log">Solo registrar</option>
              <option value="email">Enviar email</option>
              <option value="block">Bloquear automáticamente</option>
            </select>
          </div>
          <div class="modal-actions">
            <button class="btn secondary" onclick="document.getElementById('modalOverlay').style.display='none'">Cancelar</button>
            <button class="btn primary" onclick="dashboard.executeAlertConfiguration()">Configurar</button>
          </div>
        </div>
      `;
      this.showModal(modalContent);
    } catch (error) {
      window.UI?.showAlert('Error abriendo formulario de alerta', 'error');
    }
  }

  async executeAlertConfiguration() {
    const alertType = document.getElementById('alertType')?.value;
    const threshold = document.getElementById('alertThreshold')?.value;
    const period = document.getElementById('alertPeriod')?.value;
    const action = document.getElementById('alertAction')?.value;

    if (!alertType || !threshold || !period || !action) {
      window.UI?.showAlert('Por favor completa todos los campos', 'error');
      return;
    }

    try {
      await window.API.security.configureAlert({
        alertType,
        conditions: {
          threshold: parseInt(threshold),
          period: parseInt(period)
        },
        actions: {
          type: action
        }
      });
      
      window.UI?.showAlert('Alerta configurada exitosamente', 'success');
      document.getElementById('modalOverlay').style.display = 'none';
      
      // Recargar datos de alertas
      if (this.currentSection === 'alerts') {
        setTimeout(() => this.loadAlertsData(), 1000);
      }
    } catch (error) {
      window.UI?.showAlert('Error configurando alerta: ' + error.message, 'error');
    }
  }

  // Auto-refresh
  startAutoRefresh() {
    this.refreshInterval = setInterval(() => {
      if (this.currentSection === 'dashboard') {
        this.loadDashboardData();
      }
    }, this.autoRefreshTime);
  }

  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  // Cleanup al salir
  destroy() {
    this.stopAutoRefresh();
    
    // Destruir gráficos
    Object.values(this.charts).forEach(chart => {
      if (chart && chart.destroy) {
        chart.destroy();
      }
    });
    
    this.charts = {};
  }
}

// Inicialización cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', async () => {
  // Verificar autenticación
  if (!window.AuthManager?.isAuthenticated()) {
    window.location.href = '/index.html';
    return;
  }

  // Crear instancia global del dashboard
  window.dashboard = new FunctionalDashboard();
  await window.dashboard.init();

  // Configurar botones adicionales
  const newScanBtn = document.getElementById('newScanBtn');
  if (newScanBtn) {
    newScanBtn.addEventListener('click', () => window.dashboard.startVulnerabilityScan());
  }

  const generateCertBtn = document.getElementById('generateCertBtn');
  if (generateCertBtn) {
    generateCertBtn.addEventListener('click', () => window.dashboard.generateCertificate());
  }

  const addAlertBtn = document.getElementById('addAlertBtn');
  if (addAlertBtn) {
    addAlertBtn.addEventListener('click', () => window.dashboard.configureAlert());
  }

  // Cerrar modales con escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const modalOverlay = document.getElementById('modalOverlay');
      if (modalOverlay && modalOverlay.style.display !== 'none') {
        modalOverlay.style.display = 'none';
      }
    }
  });

  window.Logger?.info('Dashboard completamente inicializado y funcional');
});

// Cleanup al salir de la página
window.addEventListener('beforeunload', () => {
  if (window.dashboard) {
    window.dashboard.destroy();
  }
});
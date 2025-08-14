-- Extensiones adicionales para el sistema de seguridad

-- Tabla de alertas de seguridad
CREATE TABLE IF NOT EXISTS security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,
    conditions JSON NOT NULL,
    actions JSON NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_alert_type (alert_type),
    INDEX idx_active (is_active)
);

-- Insertar alertas de seguridad por defecto
INSERT INTO security_alerts (alert_type, conditions, actions, created_by) VALUES
('failed_login_threshold', JSON_OBJECT(
    'threshold', 5,
    'timeframe', '15 minutes',
    'action', 'login_attempt',
    'success', false
), JSON_ARRAY('lock_account', 'send_notification'), 1),

('suspicious_ip_activity', JSON_OBJECT(
    'threshold', 50,
    'timeframe', '1 hour',
    'risk_level', 'high'
), JSON_ARRAY('block_ip', 'send_alert'), 1),

('critical_vulnerability_found', JSON_OBJECT(
    'risk_score', 9.0,
    'scan_type', 'any'
), JSON_ARRAY('immediate_notification', 'create_incident'), 1);

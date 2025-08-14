-- Extensión del esquema para políticas ABAC avanzadas

-- Tabla de políticas de acceso ABAC
CREATE TABLE IF NOT EXISTS access_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    resource VARCHAR(100) NOT NULL,
    conditions JSON NOT NULL,
    actions JSON NOT NULL,
    effect ENUM('ALLOW', 'DENY') NOT NULL DEFAULT 'ALLOW',
    priority INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_resource (resource),
    INDEX idx_priority (priority),
    INDEX idx_active (is_active)
);

-- Tabla de atributos de usuario para ABAC
CREATE TABLE IF NOT EXISTS user_attributes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    attribute_name VARCHAR(50) NOT NULL,
    attribute_value TEXT NOT NULL,
    attribute_type ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_attribute (user_id, attribute_name),
    INDEX idx_attribute_name (attribute_name)
);

-- Tabla de contexto de recursos para ABAC
CREATE TABLE IF NOT EXISTS resource_contexts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100) NOT NULL,
    context_data JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_resource (resource_type, resource_id),
    INDEX idx_resource_type (resource_type)
);

-- Insertar políticas ABAC de ejemplo
INSERT INTO access_policies (name, description, resource, conditions, actions, effect, priority, created_by) VALUES
('Horario de Trabajo', 'Permitir acceso solo en horario laboral', '*', JSON_OBJECT(
    'time_restriction', JSON_OBJECT(
        'operator', 'time_between',
        'value', JSON_ARRAY(8, 18),
        'path', 'environment.time'
    )
), JSON_ARRAY('read'), 'ALLOW', 10, 1),

('Acceso de Administrador', 'Administradores tienen acceso completo', '*', JSON_OBJECT(
    'admin_role', JSON_OBJECT(
        'operator', 'in',
        'value', JSON_ARRAY('admin'),
        'path', 'user.roles'
    )
), JSON_ARRAY('*'), 'ALLOW', 100, 1),

('Bloqueo de IP Sospechosa', 'Denegar acceso desde IPs en lista negra', '*', JSON_OBJECT(
    'blacklisted_ip', JSON_OBJECT(
        'operator', 'in',
        'value', JSON_ARRAY('192.168.1.100', '10.0.0.50'),
        'path', 'request.ip'
    )
), JSON_ARRAY('*'), 'DENY', 200, 1),

('Acceso de Fin de Semana', 'Restringir operaciones críticas en fin de semana', 'users', JSON_OBJECT(
    'weekend_restriction', JSON_OBJECT(
        'operator', 'in',
        'value', JSON_ARRAY(0, 6),
        'path', 'environment.dayOfWeek'
    )
), JSON_ARRAY('delete', 'create'), 'DENY', 50, 1);

-- Insertar atributos de usuario de ejemplo
INSERT INTO user_attributes (user_id, attribute_name, attribute_value, attribute_type) VALUES
(1, 'department', 'IT', 'string'),
(1, 'clearance_level', '5', 'number'),
(1, 'can_work_weekends', 'true', 'boolean'),
(1, 'projects', '["project_a", "project_b", "project_c"]', 'json');

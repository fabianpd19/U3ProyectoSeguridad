-- Datos iniciales para la Plataforma Web Segura
-- Insertar roles básicos con permisos ABAC
INSERT INTO
    roles (name, description, permissions)
VALUES
    (
        'admin',
        'Administrador del sistema',
        JSON_OBJECT (
            'users',
            JSON_ARRAY ('create', 'read', 'update', 'delete'),
            'roles',
            JSON_ARRAY ('create', 'read', 'update', 'delete'),
            'security',
            JSON_ARRAY ('read', 'analyze', 'configure'),
            'certificates',
            JSON_ARRAY ('create', 'read', 'revoke'),
            'vulnerabilities',
            JSON_ARRAY ('scan', 'read', 'analyze')
        )
    ),
    (
        'security_analyst',
        'Analista de seguridad',
        JSON_OBJECT (
            'users',
            JSON_ARRAY ('read'),
            'security',
            JSON_ARRAY ('read', 'analyze'),
            'vulnerabilities',
            JSON_ARRAY ('scan', 'read', 'analyze'),
            'certificates',
            JSON_ARRAY ('read')
        )
    ),
    (
        'user',
        'Usuario estándar',
        JSON_OBJECT (
            'profile',
            JSON_ARRAY ('read', 'update'),
            'certificates',
            JSON_ARRAY ('read')
        )
    );

-- Insertar usuario administrador por defecto (password: Admin123!)
INSERT INTO
    users (username, email, password_hash, salt, status)
VALUES
    (
        'admin',
        'admin@secure-platform.local',
        '$2b$12$LQv3c1yqBWVHxkd0LQ4YCOdHrADfEqJpb2/GlqOEqvgAGtVlO3flm',
        '$2b$12$LQv3c1yqBWVHxkd0LQ4YCO',
        'active'
    );

-- Insertar más usuarios de ejemplo
INSERT INTO
    users (
        username,
        email,
        password_hash,
        salt,
        status,
        created_at
    )
VALUES
    (
        'security_analyst',
        'analyst@secure-platform.local',
        '$2b$12$LQv3c1yqBWVHxkd0LQ4YCOdHrADfEqJpb2/GlqOEqvgAGtVlO3flm',
        '$2b$12$LQv3c1yqBWVHxkd0LQ4YCO',
        'active',
        NOW ()
    ),
    (
        'john_doe',
        'john@secure-platform.local',
        '$2b$12$LQv3c1yqBWVHxkd0LQ4YCOdHrADfEqJpb2/GlqOEqvgAGtVlO3flm',
        '$2b$12$LQv3c1yqBWVHxkd0LQ4YCO',
        'active',
        NOW ()
    ),
    (
        'jane_smith',
        'jane@secure-platform.local',
        '$2b$12$LQv3c1yqBWVHxkd0LQ4YCOdHrADfEqJpb2/GlqOEqvgAGtVlO3flm',
        '$2b$12$LQv3c1yqBWVHxkd0LQ4YCO',
        'pending',
        NOW ()
    );

-- Asignar rol de administrador al usuario por defecto
INSERT INTO
    user_roles (user_id, role_id, assigned_by)
VALUES
    (1, 1, 1);

-- Asignar roles a los usuarios de ejemplo
INSERT INTO
    user_roles (user_id, role_id, assigned_by, assigned_at)
VALUES
    (2, 2, 1, NOW ()), -- security_analyst role
    (3, 3, 1, NOW ()), -- user role
    (4, 3, 1, NOW ());

-- user role
-- Insertar políticas ABAC de ejemplo (CORREGIDO)
INSERT INTO
    abac_policies (name, description, policy, status, created_by)
VALUES
    (
        'admin_full_access',
        'Acceso completo para administradores',
        JSON_OBJECT (
            'subject',
            JSON_OBJECT ('role', 'admin'),
            'resource',
            JSON_OBJECT ('type', '*'),
            'action',
            JSON_ARRAY ('*'),
            'environment',
            JSON_OBJECT (
                'time',
                JSON_OBJECT ('start', '00:00', 'end', '23:59')
            )
        ),
        'active',
        1
    ),
    (
        'analyst_security_access',
        'Acceso de seguridad para analistas',
        JSON_OBJECT (
            'subject',
            JSON_OBJECT ('role', 'security_analyst'),
            'resource',
            JSON_OBJECT (
                'type',
                JSON_ARRAY (
                    'vulnerabilities',
                    'security_logs',
                    'certificates'
                )
            ),
            'action',
            JSON_ARRAY ('read', 'analyze', 'scan'),
            'environment',
            JSON_OBJECT (
                'time',
                JSON_OBJECT ('start', '08:00', 'end', '18:00')
            )
        ),
        'active',
        1
    ),
    (
        'user_profile_access',
        'Acceso a perfil para usuarios',
        JSON_OBJECT (
            'subject',
            JSON_OBJECT ('role', 'user'),
            'resource',
            JSON_OBJECT ('type', 'profile', 'owner', 'self'),
            'action',
            JSON_ARRAY ('read', 'update'),
            'environment',
            JSON_OBJECT ()
        ),
        'active',
        1
    );

-- Insertar configuraciones de alertas de ejemplo
INSERT INTO
    security_alerts (
        type,
        severity,
        title,
        description,
        conditions,
        actions,
        status,
        created_by
    )
VALUES
    (
        'failed_login',
        'high',
        'Intentos de login fallidos',
        'Múltiples intentos de login fallidos detectados',
        JSON_OBJECT (
            'threshold',
            5,
            'timeframe',
            300,
            'action',
            'block_ip'
        ),
        JSON_OBJECT (
            'email',
            JSON_ARRAY ('admin@secure-platform.local'),
            'block_duration',
            3600
        ),
        'active',
        1
    ),
    (
        'vulnerability_detected',
        'critical',
        'Vulnerabilidad crítica detectada',
        'Se detectó una vulnerabilidad de alta severidad',
        JSON_OBJECT (
            'severity',
            JSON_ARRAY ('critical', 'high'),
            'auto_scan',
            true
        ),
        JSON_OBJECT (
            'email',
            JSON_ARRAY (
                'admin@secure-platform.local',
                'analyst@secure-platform.local'
            ),
            'create_ticket',
            true
        ),
        'active',
        1
    ),
    (
        'certificate_expiry',
        'medium',
        'Certificado próximo a expirar',
        'Certificado expirará en los próximos 30 días',
        JSON_OBJECT ('days_before', 30, 'check_frequency', 'daily'),
        JSON_OBJECT (
            'email',
            JSON_ARRAY ('admin@secure-platform.local'),
            'renew_auto',
            false
        ),
        'active',
        1
    );

-- Insertar logs de seguridad de ejemplo
INSERT INTO
    security_logs (
        user_id,
        action,
        resource,
        ip_address,
        success,
        details,
        risk_level,
        created_at
    )
VALUES
    (
        1,
        'system_init',
        'database',
        '127.0.0.1',
        TRUE,
        JSON_OBJECT ('message', 'Sistema inicializado correctamente'),
        'low',
        NOW ()
    ),
    (
        1,
        'login',
        'auth',
        '192.168.1.100',
        TRUE,
        JSON_OBJECT ('method', '2fa', 'device', 'desktop'),
        'low',
        DATE_SUB (NOW (), INTERVAL 1 HOUR)
    ),
    (
        2,
        'vulnerability_scan',
        'security',
        '192.168.1.101',
        TRUE,
        JSON_OBJECT ('scan_type', 'full', 'findings', 3),
        'medium',
        DATE_SUB (NOW (), INTERVAL 2 HOUR)
    ),
    (
        3,
        'failed_login',
        'auth',
        '203.0.113.45',
        FALSE,
        JSON_OBJECT ('reason', 'invalid_password', 'attempts', 3),
        'high',
        DATE_SUB (NOW (), INTERVAL 30 MINUTE)
    ),
    (
        1,
        'certificate_create',
        'certificates',
        '192.168.1.100',
        TRUE,
        JSON_OBJECT ('type', 'ssl', 'domain', 'secure-platform.local'),
        'low',
        DATE_SUB (NOW (), INTERVAL 3 HOUR)
    );

-- Insertar certificados de ejemplo
INSERT INTO
    certificates (
        name,
        type,
        subject,
        issuer,
        serial_number,
        valid_from,
        valid_to,
        status,
        created_by
    )
VALUES
    (
        'Secure Platform SSL',
        'ssl',
        'CN=secure-platform.local',
        'CN=Secure Platform CA',
        'ABC123456789',
        DATE_SUB (NOW (), INTERVAL 30 DAY),
        DATE_ADD (NOW (), INTERVAL 335 DAY),
        'active',
        1
    ),
    (
        'API Certificate',
        'client',
        'CN=api.secure-platform.local',
        'CN=Secure Platform CA',
        'DEF987654321',
        DATE_SUB (NOW (), INTERVAL 15 DAY),
        DATE_ADD (NOW (), INTERVAL 350 DAY),
        'active',
        1
    ),
    (
        'Test Certificate',
        'ssl',
        'CN=test.secure-platform.local',
        'CN=Test CA',
        'GHI456789123',
        DATE_SUB (NOW (), INTERVAL 100 DAY),
        DATE_SUB (NOW (), INTERVAL 10 DAY),
        'expired',
        1
    );

-- Insertar vulnerabilidades de ejemplo
INSERT INTO
    vulnerabilities (
        name,
        description,
        severity,
        cvss_score,
        cve_id,
        affected_systems,
        status,
        discovered_by,
        created_at
    )
VALUES
    (
        'SQL Injection in Login Form',
        'Posible inyección SQL en el formulario de login',
        'high',
        8.5,
        'CVE-2024-0001',
        JSON_ARRAY ('web_app', 'database'),
        'open',
        1,
        DATE_SUB (NOW (), INTERVAL 2 DAY)
    ),
    (
        'Weak Password Policy',
        'La política de contraseñas actual es débil',
        'medium',
        5.2,
        NULL,
        JSON_ARRAY ('auth_system'),
        'in_progress',
        2,
        DATE_SUB (NOW (), INTERVAL 5 DAY)
    ),
    (
        'Outdated SSL Certificate',
        'Certificado SSL próximo a expirar',
        'low',
        3.1,
        NULL,
        JSON_ARRAY ('web_server'),
        'resolved',
        1,
        DATE_SUB (NOW (), INTERVAL 10 DAY)
    );

-- Insertar configuraciones del sistema
INSERT INTO
    system_config (
        config_key,
        config_value,
        description,
        category,
        created_by
    )
VALUES
    (
        'max_login_attempts',
        '5',
        'Máximo número de intentos de login antes de bloquear',
        'security',
        1
    ),
    (
        'session_timeout',
        '3600',
        'Tiempo de expiración de sesión en segundos',
        'security',
        1
    ),
    (
        'password_min_length',
        '8',
        'Longitud mínima de contraseña',
        'security',
        1
    ),
    (
        '2fa_required',
        'true',
        'Requerir autenticación de dos factores',
        'security',
        1
    ),
    (
        'vulnerability_scan_frequency',
        '24',
        'Frecuencia de escaneo de vulnerabilidades en horas',
        'security',
        1
    ),
    (
        'certificate_check_frequency',
        '24',
        'Frecuencia de verificación de certificados en horas',
        'security',
        1
    ),
    (
        'log_retention_days',
        '90',
        'Días de retención de logs de seguridad',
        'logging',
        1
    ),
    (
        'alert_email_enabled',
        'true',
        'Habilitar alertas por email',
        'notifications',
        1
    );

-- Mensaje final
SELECT
    'Base de datos poblada exitosamente con datos de ejemplo' AS message;

SELECT
    'Credenciales por defecto:' AS info;

SELECT
    'Admin - Usuario: admin, Email: admin@secure-platform.local, Password: Admin123!' AS admin_credentials;

SELECT
    'Analista - Usuario: security_analyst, Email: analyst@secure-platform.local, Password: Admin123!' AS analyst_credentials;

SELECT
    'IMPORTANTE: Cambiar las contraseñas por defecto después del primer login' AS warning;
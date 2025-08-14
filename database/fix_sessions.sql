-- Crear tabla de sesiones compatible con express-mysql-session
-- Renombrar la tabla sessions actual para preservar los datos
USE secure_platform;

ALTER TABLE sessions
RENAME TO user_sessions;

-- Crear nueva tabla sessions para express-mysql-session
CREATE TABLE
    sessions (
        session_id VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
        expires BIGINT (20) UNSIGNED NOT NULL,
        data MEDIUMTEXT COLLATE utf8mb4_bin,
        PRIMARY KEY (session_id)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_bin;
-- ============================================================
-- Esquema nativo para MariaDB 11.4 - SEIJAKUTECH
-- Base de datos: seijakutech_db
-- Seguridad: Encriptación Bcrypt ($2b$10$) + Consultas Preparadas (?) Anti-SQLi
-- ============================================================

CREATE DATABASE IF NOT EXISTS seijakutech_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE seijakutech_db;

CREATE TABLE IF NOT EXISTS usuarios (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  nombre VARCHAR(100) DEFAULT 'Administrador SEIJAKUTECH',
  correo VARCHAR(120) NOT NULL DEFAULT 'seijakutech@gmail.com' COMMENT 'Solo correos @gmail.com permitidos',
  usuario VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL COMMENT 'Hash Bcrypt ($2b$10$) - Prohibido texto plano',
  foto_perfil LONGTEXT DEFAULT NULL COMMENT 'Foto de perfil persistente en Base64/DataURL',
  bienvenida_enviada TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = Correo de bienvenida ya enviado en primer registro',
  rol VARCHAR(32) NOT NULL DEFAULT 'cliente',
  intentos_fallidos TINYINT UNSIGNED NOT NULL DEFAULT 0,
  bloqueado_hasta DATETIME DEFAULT NULL,
  fecha_registro TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_usuarios_usuario (usuario),
  UNIQUE KEY uq_usuarios_correo (correo),
  CONSTRAINT chk_correo_gmail CHECK (correo = 'administrador' OR correo LIKE '%@gmail.com')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Usuario Administrador Exclusivo con excepción de login sin @gmail.com (administrador / Administrador.2004)
INSERT INTO usuarios (nombre, correo, usuario, password_hash, foto_perfil, bienvenida_enviada, rol, fecha_registro)
VALUES (
  'Administrador SEIJAKUTECH',
  'administrador',
  'administrador',
  '$2b$10$ur1I/B1A71/WIMMe1/QdsuM6YJO47LVIt1rz32mepqZvCqO9ZPYna',
  NULL,
  1,
  'administrador',
  CURRENT_TIMESTAMP()
)
ON DUPLICATE KEY UPDATE
  nombre = VALUES(nombre),
  correo = VALUES(correo),
  password_hash = VALUES(password_hash),
  rol = VALUES(rol);

-- Consulta preparada nativa en MariaDB para eliminar permanentemente un usuario registrado:
-- PREPARE stmt_delete_user FROM 'DELETE FROM usuarios WHERE LOWER(correo) = ? AND rol <> ''administrador''';
-- EXECUTE stmt_delete_user USING @correo_eliminar;
-- DEALLOCATE PREPARE stmt_delete_user;

CREATE TABLE IF NOT EXISTS pedidos (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  folio VARCHAR(32) NOT NULL,
  detalle_json LONGTEXT NOT NULL,
  total INT UNSIGNED NOT NULL DEFAULT 0,
  fecha_pedido TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_pedidos_folio (folio)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

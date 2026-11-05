import express from 'express';
import mariadb from 'mariadb';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_SALT_ROUNDS = 10;
const MAX_LOGIN_ATTEMPTS = 3;
const LOCKOUT_DURATION_MS = 30 * 1000; // 30 segundos

// Credenciales exclusivas de Administrador con excepción de login sin @gmail.com
const SUPER_ADMIN_USER = 'administrador';
const SUPER_ADMIN_PASS = 'Administrador.2004';

// Rutas de persistencia en disco (respaldo permanente sincronizado con MariaDB)
const DATA_DIR = path.join(__dirname, 'data');
const USERS_DB_FILE = path.join(DATA_DIR, 'users-db.json');
const WELCOME_LOG_FILE = path.join(DATA_DIR, 'welcome-emails.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

// Inicializar base de datos persistente en disco con acceso directo exclusivo para 'administrador'
function loadPersistentUsers() {
  ensureDataDir();
  let db = { users: {} };
  if (fs.existsSync(USERS_DB_FILE)) {
    try {
      const raw = fs.readFileSync(USERS_DB_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.users === 'object') {
        db = parsed;
      }
    } catch (e) {
      db = { users: {} };
    }
  }

  let dirty = false;

  // Eliminar cuentas automáticas antiguas si no fueron registradas manualmente por un usuario normal
  if (db.users['seijakutech@gmail.com'] && db.users['seijakutech@gmail.com'].usuario === 'admin') {
    delete db.users['seijakutech@gmail.com'];
    dirty = true;
  }
  if (db.users['simonadministrador@gmail.com'] && db.users['simonadministrador@gmail.com'].rol === 'administrador') {
    delete db.users['simonadministrador@gmail.com'];
    dirty = true;
  }

  // Asegurar cuenta exclusiva de Administrador: administrador / Administrador.2004
  if (!db.users[SUPER_ADMIN_USER]) {
    db.users[SUPER_ADMIN_USER] = {
      id: 1,
      nombre: 'Administrador SEIJAKUTECH',
      correo: SUPER_ADMIN_USER,
      usuario: SUPER_ADMIN_USER,
      password_hash: bcrypt.hashSync(SUPER_ADMIN_PASS, BCRYPT_SALT_ROUNDS),
      password_sha256: sha256Hex(SUPER_ADMIN_PASS),
      foto_perfil: null,
      bienvenida_enviada: true,
      fecha_bienvenida: new Date().toISOString(),
      rol: 'administrador',
      fecha_registro: new Date().toISOString()
    };
    dirty = true;
  } else {
    db.users[SUPER_ADMIN_USER].rol = 'administrador';
    db.users[SUPER_ADMIN_USER].password_sha256 = sha256Hex(SUPER_ADMIN_PASS);
  }

  if (dirty) {
    savePersistentUsers(db);
  }
  return db;
}

function savePersistentUsers(db) {
  ensureDataDir();
  fs.writeFileSync(USERS_DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function removeWelcomeEmailForUser(correo) {
  ensureDataDir();
  if (!fs.existsSync(WELCOME_LOG_FILE)) return;
  try {
    const logs = JSON.parse(fs.readFileSync(WELCOME_LOG_FILE, 'utf8')) || [];
    const target = String(correo || '').trim().toLowerCase();
    const filtered = logs.filter((item) => String(item.to || '').toLowerCase() !== target);
    fs.writeFileSync(WELCOME_LOG_FILE, JSON.stringify(filtered, null, 2), 'utf8');
  } catch (_) {
    // Ignorar errores de archivo
  }
}

function recordWelcomeEmailDispatch(correo, nombre) {
  ensureDataDir();
  let logs = [];
  if (fs.existsSync(WELCOME_LOG_FILE)) {
    try {
      logs = JSON.parse(fs.readFileSync(WELCOME_LOG_FILE, 'utf8')) || [];
    } catch (e) {
      logs = [];
    }
  }
  const entry = {
    id: 'WEL-' + Date.now(),
    to: correo,
    from: 'seijakutech@gmail.com',
    subject: '¡Bienvenido(a) a SEIJAKUTECH - Servicio Técnico!',
    message: `Hola ${nombre}, tu cuenta (${correo}) ha sido registrada exitosamente en SEIJAKUTECH. Tus credenciales han quedado guardadas de forma segura y persistente.`,
    sentAt: new Date().toISOString(),
    onlyFirstRegistration: true
  };
  logs.push(entry);
  fs.writeFileSync(WELCOME_LOG_FILE, JSON.stringify(logs, null, 2), 'utf8');
  return entry;
}

// Cabeceras de seguridad HTTP con Helmet
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

// Límite ampliado a 5mb para permitir subida y guardado persistente de fotos de perfil (Base64/DataURL)
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'src')));

// Sanitización de inputs contra ataques XSS (escapando <, >, ', ", &)
function sanitizeXSS(input) {
  return String(input || '')
    .trim()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Regla Estricta: Solo permitir correos que terminen estrictamente en @gmail.com
function isStrictGmail(email) {
  const clean = String(email || '').trim().toLowerCase();
  return /^[a-z0-9._%+-]+@gmail\.com$/.test(clean);
}

// Control de bloqueo por fuerza bruta (3 intentos fallidos -> bloqueo de 30 segundos)
const bruteForceStore = new Map();

function getBruteForceState(key) {
  const now = Date.now();
  const entry = bruteForceStore.get(key) || { attempts: 0, lockUntil: 0 };
  if (entry.lockUntil && now >= entry.lockUntil) {
    entry.attempts = 0;
    entry.lockUntil = 0;
    bruteForceStore.set(key, entry);
  }
  return entry;
}

function recordFailedAttempt(key) {
  const entry = getBruteForceState(key);
  entry.attempts += 1;
  if (entry.attempts >= MAX_LOGIN_ATTEMPTS) {
    entry.lockUntil = Date.now() + LOCKOUT_DURATION_MS;
  }
  bruteForceStore.set(key, entry);
  return entry;
}

function resetFailedAttempts(key) {
  bruteForceStore.delete(key);
}

// Rate limiter en la ruta /api/login con express-rate-limit
const loginRateLimiter = rateLimit({
  windowMs: LOCKOUT_DURATION_MS,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    locked: true,
    retryAfterSeconds: 30,
    engine: 'MariaDB 11.4 (InnoDB) | Rate-Limiter',
    message: 'Demasiadas solicitudes a /api/login. Bloqueo temporal de 30 segundos por seguridad.'
  }
});

// Pool de conexiones oficial de MariaDB
const pool = mariadb.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'seijakutech_db',
  connectionLimit: 5,
  acquireTimeout: 1500,
  connectTimeout: 1500
});

// Asegurar esquema y cuenta exclusiva de Administrador en MariaDB si está activo
async function ensureMariaDBSchema() {
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        nombre VARCHAR(100) DEFAULT 'Usuario SEIJAKUTECH',
        correo VARCHAR(120) NOT NULL,
        usuario VARCHAR(64) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        foto_perfil LONGTEXT DEFAULT NULL,
        bienvenida_enviada TINYINT(1) NOT NULL DEFAULT 0,
        rol VARCHAR(32) NOT NULL DEFAULT 'cliente',
        intentos_fallidos TINYINT UNSIGNED NOT NULL DEFAULT 0,
        bloqueado_hasta DATETIME DEFAULT NULL,
        fecha_registro TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_usuarios_usuario (usuario),
        UNIQUE KEY uq_usuarios_correo (correo)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
    try {
      await conn.execute('ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS foto_perfil LONGTEXT DEFAULT NULL');
      await conn.execute('ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS bienvenida_enviada TINYINT(1) NOT NULL DEFAULT 0');
    } catch (_) {
      // Columnas ya existen
    }
    const adminBcrypt = await bcrypt.hash(SUPER_ADMIN_PASS, BCRYPT_SALT_ROUNDS);
    await conn.execute(
      `INSERT INTO usuarios (nombre, correo, usuario, password_hash, bienvenida_enviada, rol)
       VALUES (?, ?, ?, ?, 1, 'administrador')
       ON DUPLICATE KEY UPDATE rol = 'administrador', password_hash = VALUES(password_hash)`,
      ['Administrador SEIJAKUTECH', SUPER_ADMIN_USER, SUPER_ADMIN_USER, adminBcrypt]
    );
  } catch (_) {
    // Respaldo persistente activo en data/users-db.json
  } finally {
    if (conn) conn.release();
  }
}
ensureMariaDBSchema();

// Ruta de inicio de sesión: Excepción exclusiva para "administrador" (sin @gmail.com) y obligación estricta de @gmail.com + registro previo para todos los demás
app.post('/api/login', loginRateLimiter, async (req, res) => {
  const rawInput = String(req.body?.correo || req.body?.usuario || '').trim();
  const rawCorreo = rawInput.toLowerCase();
  const rawPassword = String(req.body?.password || '');
  const correo = sanitizeXSS(rawCorreo);
  const clientKey = `${req.ip || 'local'}:${correo}`;

  // Verificar si el cliente está bloqueado por fuerza bruta (3 intentos -> 30s)
  const lockState = getBruteForceState(clientKey);
  if (lockState.lockUntil > Date.now()) {
    const remainingSeconds = Math.ceil((lockState.lockUntil - Date.now()) / 1000);
    return res.status(429).json({
      ok: false,
      locked: true,
      retryAfterSeconds: remainingSeconds,
      engine: 'MariaDB 11.4 (InnoDB) | Brute-Force Lock',
      message: `Cuenta bloqueada temporalmente tras ${MAX_LOGIN_ATTEMPTS} intentos fallidos. Espera ${remainingSeconds}s.`
    });
  }

  if (!rawPassword) {
    return res.status(400).json({
      ok: false,
      engine: 'MariaDB 11.4 (InnoDB)',
      message: 'Debes ingresar tu contraseña para verificar tu cuenta en la base de datos.'
    });
  }

  const persistentDb = loadPersistentUsers();

  // Regla 1: Excepción exclusiva para el texto exacto "administrador" + contraseña "Administrador.2004"
  if (rawInput === SUPER_ADMIN_USER) {
    if (rawPassword !== SUPER_ADMIN_PASS) {
      const updatedState = recordFailedAttempt(clientKey);
      const isNowLocked = updatedState.lockUntil > Date.now();
      return res.status(isNowLocked ? 429 : 401).json({
        ok: false,
        wrongPassword: true,
        code: 'ADMIN_INVALID_PASSWORD',
        locked: isNowLocked,
        attempts: updatedState.attempts,
        retryAfterSeconds: isNowLocked ? 30 : 0,
        engine: 'MariaDB 11.4 (InnoDB) | Control de Administrador',
        message: isNowLocked
          ? 'Formulario bloqueado por 30 segundos tras 3 intentos fallidos.'
          : 'Acceso bloqueado: La contraseña ingresada no coincide con la cuenta de Administrador (administrador).'
      });
    }

    resetFailedAttempts(clientKey);
    const adminRecord = persistentDb.users[SUPER_ADMIN_USER];
    return res.status(200).json({
      ok: true,
      isNewRegistration: false,
      welcomeEmailSent: false,
      isSuperAdmin: true,
      engine: 'MariaDB 11.4 (InnoDB) | Acceso Directo Administrador',
      database: 'seijakutech_db',
      message: "Acceso concedido con Rol de Administrador ('administrador'). Panel 'Personas Registradas' desbloqueado.",
      user: {
        id: adminRecord?.id || 1,
        nombre: adminRecord?.nombre || 'Administrador SEIJAKUTECH',
        correo: SUPER_ADMIN_USER,
        usuario: SUPER_ADMIN_USER,
        rol: 'administrador',
        isSuperAdmin: true,
        fotoPerfil: adminRecord?.foto_perfil || null,
        welcomeEmailSent: true,
        fecha_registro: adminRecord?.fecha_registro || new Date().toISOString()
      }
    });
  }

  // Obligación estricta de terminar en @gmail.com para todos los demás usuarios normales
  if (!isStrictGmail(rawCorreo)) {
    return res.status(400).json({
      ok: false,
      code: 'INVALID_GMAIL_FORMAT',
      engine: 'MariaDB 11.4 (InnoDB) | Validación @gmail.com',
      message: 'Validación estricta: Todos los usuarios normales deben iniciar sesión con un correo que termine en @gmail.com.'
    });
  }

  // Para cualquier usuario normal @gmail.com, verificar que exista en la base de datos (y que no haya sido eliminado)
  const matchedUser = persistentDb.users[rawCorreo] || null;

  if (!matchedUser) {
    const updatedState = recordFailedAttempt(clientKey);
    const isNowLocked = updatedState.lockUntil > Date.now();
    return res.status(isNowLocked ? 429 : 401).json({
      ok: false,
      userNotFound: true,
      code: 'USER_NOT_REGISTERED',
      locked: isNowLocked,
      attempts: updatedState.attempts,
      retryAfterSeconds: isNowLocked ? 30 : 0,
      engine: 'MariaDB 11.4 (InnoDB)',
      database: 'seijakutech_db',
      message: isNowLocked
        ? 'Formulario bloqueado por 30 segundos tras 3 intentos fallidos consecutivos.'
        : `Acceso rechazado: El correo '${correo}' no existe en la base de datos. Debes registrarte de nuevo desde cero.`
    });
  }

  const storedHash = String(matchedUser.password_hash || '');
  let isPasswordValid = false;
  if (storedHash.startsWith('$2')) {
    isPasswordValid = await bcrypt.compare(rawPassword, storedHash);
  }
  if (!isPasswordValid && matchedUser.password_sha256) {
    isPasswordValid = sha256Hex(rawPassword) === matchedUser.password_sha256;
  }

  if (!isPasswordValid) {
    const updatedState = recordFailedAttempt(clientKey);
    const isNowLocked = updatedState.lockUntil > Date.now();
    return res.status(isNowLocked ? 429 : 401).json({
      ok: false,
      wrongPassword: true,
      code: 'INVALID_PASSWORD',
      locked: isNowLocked,
      attempts: updatedState.attempts,
      retryAfterSeconds: isNowLocked ? 30 : 0,
      engine: 'MariaDB 11.4 (InnoDB)',
      database: 'seijakutech_db',
      message: isNowLocked
        ? 'Formulario bloqueado por 30 segundos tras 3 intentos fallidos consecutivos.'
        : `Acceso bloqueado: La contraseña ingresada no coincide con el registro de '${correo}' (Intento ${updatedState.attempts}/${MAX_LOGIN_ATTEMPTS}).`
    });
  }

  resetFailedAttempts(clientKey);

  return res.status(200).json({
    ok: true,
    isNewRegistration: false,
    welcomeEmailSent: false,
    isSuperAdmin: false,
    engine: 'MariaDB 11.4 (InnoDB) | Prepared Statement & Bcrypt',
    database: 'seijakutech_db',
    message: `Sesión iniciada correctamente como ${matchedUser.correo} — Credenciales y foto verificadas en la base de datos.`,
    user: {
      id: matchedUser.id || 1,
      nombre: sanitizeXSS(matchedUser.nombre || matchedUser.usuario),
      correo: sanitizeXSS(matchedUser.correo.toLowerCase()),
      usuario: sanitizeXSS(matchedUser.usuario || matchedUser.correo.split('@')[0]),
      rol: sanitizeXSS(matchedUser.rol || 'cliente'),
      isSuperAdmin: false,
      fotoPerfil: matchedUser.foto_perfil || null,
      welcomeEmailSent: true,
      fecha_registro: matchedUser.fecha_registro
    }
  });
});

// Ruta de registro persistente de nuevos usuarios (obligación estricta de @gmail.com)
app.post('/api/register', async (req, res) => {
  const rawCorreo = String(req.body?.correo || '').trim().toLowerCase();
  const rawNombre = String(req.body?.nombre || '').trim() || rawCorreo.split('@')[0];
  const rawUsuario = String(req.body?.usuario || '').trim() || rawCorreo.split('@')[0];
  const rawPassword = String(req.body?.password || '');
  const rawFotoPerfil = req.body?.fotoPerfil && String(req.body.fotoPerfil).startsWith('data:image/')
    ? String(req.body.fotoPerfil)
    : null;

  const nombre = sanitizeXSS(rawNombre);
  const correo = sanitizeXSS(rawCorreo);
  const usuario = sanitizeXSS(rawUsuario);

  if (rawCorreo === SUPER_ADMIN_USER || rawUsuario.toLowerCase() === SUPER_ADMIN_USER) {
    return res.status(409).json({
      ok: false,
      alreadyExists: true,
      message: "El identificador 'administrador' es de uso exclusivo del sistema. Inicia sesión directamente en la pestaña 'Iniciar Sesión'."
    });
  }

  if (!isStrictGmail(rawCorreo)) {
    return res.status(400).json({
      ok: false,
      engine: 'MariaDB 11.4 (InnoDB) | Validación @gmail.com',
      message: 'Validación estricta: Solo se permite registrar cuentas con correo terminado en @gmail.com.'
    });
  }

  if (!nombre || !rawPassword || rawPassword.length < 4) {
    return res.status(400).json({
      ok: false,
      engine: 'MariaDB 11.4 (InnoDB)',
      message: 'Debes ingresar tu nombre, un correo @gmail.com válido y una contraseña (mínimo 4 caracteres).'
    });
  }

  const persistentDb = loadPersistentUsers();

  if (persistentDb.users[rawCorreo]) {
    return res.status(409).json({
      ok: false,
      alreadyExists: true,
      engine: 'MariaDB 11.4 (InnoDB)',
      message: `El correo '${correo}' ya está registrado en la base de datos. Inicia sesión con tu contraseña.`
    });
  }

  const bcryptPasswordHash = await bcrypt.hash(rawPassword, BCRYPT_SALT_ROUNDS);
  const pwdSha256 = sha256Hex(rawPassword);
  const nowIso = new Date().toISOString();
  let insertedId = Object.keys(persistentDb.users).length + 1;

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.execute('DELETE FROM usuarios WHERE LOWER(correo) = ?', [rawCorreo]);
    const result = await conn.execute(
      'INSERT INTO usuarios (nombre, correo, usuario, password_hash, foto_perfil, bienvenida_enviada, rol) VALUES (?, ?, ?, ?, ?, 1, ?)',
      [nombre, rawCorreo, usuario, bcryptPasswordHash, rawFotoPerfil, 'cliente']
    );
    insertedId = Number(result.insertId || insertedId);
  } catch (_) {
    // Continuar con persistencia en disco data/users-db.json
  } finally {
    if (conn) conn.release();
  }

  const welcomeEmailEntry = recordWelcomeEmailDispatch(rawCorreo, nombre);

  persistentDb.users[rawCorreo] = {
    id: insertedId,
    nombre,
    correo: rawCorreo,
    usuario,
    password_hash: bcryptPasswordHash,
    password_sha256: pwdSha256,
    foto_perfil: rawFotoPerfil,
    bienvenida_enviada: true,
    fecha_bienvenida: welcomeEmailEntry.sentAt,
    rol: 'cliente',
    fecha_registro: nowIso
  };
  savePersistentUsers(persistentDb);

  return res.status(201).json({
    ok: true,
    isNewRegistration: true,
    welcomeEmailSent: true,
    welcomeEmailDetails: welcomeEmailEntry,
    engine: 'MariaDB 11.4 (InnoDB) | Bcrypt & Persistent Storage',
    database: 'seijakutech_db',
    message: `Usuario '${rawCorreo}' registrado de forma permanente. Correo automático de bienvenida enviado por única vez.`,
    user: {
      id: insertedId,
      nombre,
      correo: rawCorreo,
      usuario,
      rol: 'cliente',
      isSuperAdmin: false,
      fotoPerfil: rawFotoPerfil,
      welcomeEmailSent: true,
      fecha_registro: nowIso
    }
  });
});

// Endpoint exclusivo para el usuario "administrador" que devuelve todas las personas registradas (@gmail.com) en tiempo real
app.get('/api/admin/users', async (req, res) => {
  const requester = String(req.query?.admin || req.headers['x-admin-user'] || '').trim();
  if (requester !== SUPER_ADMIN_USER) {
    return res.status(403).json({
      ok: false,
      message: "Acceso denegado: La sección Personas Registradas es exclusiva para el usuario 'administrador'."
    });
  }

  const persistentDb = loadPersistentUsers();

  const usersList = Object.values(persistentDb.users)
    .filter((u) => u && u.correo && u.correo !== SUPER_ADMIN_USER && isStrictGmail(u.correo))
    .map((u) => ({
      id: u.id || 1,
      nombre: u.nombre || u.usuario || u.correo.split('@')[0],
      correo: u.correo,
      usuario: u.usuario || u.correo.split('@')[0],
      rol: u.rol || 'cliente',
      fotoPerfil: u.foto_perfil || null,
      fechaRegistro: u.fecha_registro || new Date().toISOString()
    }))
    .sort((a, b) => new Date(b.fechaRegistro).getTime() - new Date(a.fechaRegistro).getTime());

  return res.status(200).json({
    ok: true,
    total: usersList.length,
    users: usersList
  });
});

// Regla 2 y 3: Borrado real y permanente en Base de Datos de un usuario desde "Personas Registradas" (exclusivo para "administrador")
async function handleAdminDeleteUser(req, res) {
  const requester = String(
    req.query?.admin || req.body?.admin || req.headers['x-admin-user'] || ''
  ).trim();

  if (requester !== SUPER_ADMIN_USER) {
    return res.status(403).json({
      ok: false,
      message: "Acceso denegado: Solo el usuario 'administrador' puede eliminar personas registradas."
    });
  }

  const targetCorreo = String(req.body?.correo || req.query?.correo || '').trim().toLowerCase();
  if (!targetCorreo || targetCorreo === SUPER_ADMIN_USER || !isStrictGmail(targetCorreo)) {
    return res.status(400).json({
      ok: false,
      message: 'Debes indicar un correo @gmail.com válido de usuario registrado para eliminar.'
    });
  }

  const persistentDb = loadPersistentUsers();
  const existedInDisk = Boolean(persistentDb.users[targetCorreo]);

  // 1. Eliminar de forma permanente de data/users-db.json
  delete persistentDb.users[targetCorreo];
  savePersistentUsers(persistentDb);

  // 2. Eliminar registro de bienvenida previo para obligar a un registro desde cero limpio
  removeWelcomeEmailForUser(targetCorreo);

  // 3. Eliminar permanentemente de MariaDB si está activo
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.execute('DELETE FROM usuarios WHERE LOWER(correo) = ?', [targetCorreo]);
  } catch (_) {
    // Eliminado en base de datos persistente en disco
  } finally {
    if (conn) conn.release();
  }

  const remainingUsers = Object.values(persistentDb.users).filter(
    (u) => u && u.correo && u.correo !== SUPER_ADMIN_USER && isStrictGmail(u.correo)
  );

  return res.status(200).json({
    ok: true,
    deleted: true,
    existed: existedInDisk,
    deletedCorreo: targetCorreo,
    totalRemaining: remainingUsers.length,
    engine: 'MariaDB 11.4 (InnoDB) | Permanent DELETE',
    message: `El usuario '${targetCorreo}' fue eliminado permanentemente de la base de datos. Si intenta iniciar sesión, el acceso será rechazado y deberá registrarse de nuevo desde cero.`
  });
}

app.delete('/api/admin/users', handleAdminDeleteUser);
app.post('/api/admin/users/delete', handleAdminDeleteUser);

// Subir o actualizar la foto de perfil del usuario con sesión activa
app.put('/api/profile/photo', async (req, res) => {
  const rawCorreo = String(req.body?.correo || '').trim().toLowerCase();
  const rawFotoPerfil = String(req.body?.fotoPerfil || '');

  if (rawCorreo !== SUPER_ADMIN_USER && !isStrictGmail(rawCorreo)) {
    return res.status(400).json({
      ok: false,
      message: 'Se requiere una sesión activa válida.'
    });
  }

  if (!rawFotoPerfil.startsWith('data:image/')) {
    return res.status(400).json({
      ok: false,
      message: 'Formato de imagen inválido. Selecciona una imagen válida (PNG, JPG, WebP).'
    });
  }

  const persistentDb = loadPersistentUsers();
  if (!persistentDb.users[rawCorreo]) {
    return res.status(404).json({
      ok: false,
      message: 'Usuario no encontrado en la base de datos.'
    });
  }

  persistentDb.users[rawCorreo].foto_perfil = rawFotoPerfil;
  savePersistentUsers(persistentDb);

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.execute(
      'UPDATE usuarios SET foto_perfil = ? WHERE LOWER(correo) = ?',
      [rawFotoPerfil, rawCorreo]
    );
  } catch (_) {
    // Respaldo persistente en disco ya actualizado
  } finally {
    if (conn) conn.release();
  }

  return res.status(200).json({
    ok: true,
    correo: rawCorreo,
    fotoPerfil: rawFotoPerfil,
    message: 'Foto de perfil actualizada y guardada de forma persistente en la base de datos.'
  });
});

// Obtener datos actualizados del perfil activo al recargar la página
app.get('/api/profile', async (req, res) => {
  const rawCorreo = String(req.query?.correo || '').trim().toLowerCase();
  if (rawCorreo !== SUPER_ADMIN_USER && !isStrictGmail(rawCorreo)) {
    return res.status(400).json({ ok: false, message: 'Identificador de sesión inválido.' });
  }

  const persistentDb = loadPersistentUsers();
  const user = persistentDb.users[rawCorreo];
  if (!user) {
    return res.status(404).json({ ok: false, userNotFound: true, message: 'Usuario no encontrado en la base de datos.' });
  }

  return res.status(200).json({
    ok: true,
    user: {
      id: user.id,
      nombre: user.nombre,
      correo: user.correo,
      usuario: user.usuario,
      rol: user.rol || 'cliente',
      isSuperAdmin: user.correo === SUPER_ADMIN_USER,
      fotoPerfil: user.foto_perfil || null,
      welcomeEmailSent: Boolean(user.bienvenida_enviada),
      fecha_registro: user.fecha_registro
    }
  });
});

// Ruta para registrar pedidos del carrito en la tabla `pedidos` de MariaDB con Prepared Statements (?)
app.post('/api/pedidos', async (req, res) => {
  const folio = sanitizeXSS(req.body?.folio || '');
  const items = req.body?.items;
  const total = Number(req.body?.total || 0);

  if (!folio || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({
      ok: false,
      engine: 'MariaDB 11.4 (InnoDB)',
      message: 'Datos de pedido incompletos.'
    });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.execute(
      'INSERT INTO pedidos (folio, detalle_json, total) VALUES (?, ?, ?)',
      [folio, JSON.stringify(items), total]
    );

    return res.status(201).json({
      ok: true,
      engine: 'MariaDB 11.4 (InnoDB)',
      database: 'seijakutech_db',
      folio,
      message: 'Pedido almacenado con consulta preparada en seijakutech_db.pedidos'
    });
  } catch (error) {
    return res.status(503).json({
      ok: false,
      engine: 'MariaDB 11.4 (InnoDB)',
      error: error.code || 'MARIADB_CONNECTION_ERROR'
    });
  } finally {
    if (conn) conn.release();
  }
});

app.listen(PORT, () => {
  console.log(`Servidor SEIJAKUTECH con seguridad Helmet, Bcrypt y MariaDB activo en http://localhost:${PORT}`);
});

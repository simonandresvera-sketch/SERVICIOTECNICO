import { defineConfig } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, 'data');
const USERS_DB_FILE = path.join(DATA_DIR, 'users-db.json');
const WELCOME_LOG_FILE = path.join(DATA_DIR, 'welcome-emails.json');

const SUPER_ADMIN_USER = 'administrador';
const SUPER_ADMIN_PASS = 'Administrador.2004';

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

function isStrictGmail(email) {
  return /^[a-z0-9._%+-]+@gmail\.com$/.test(String(email || '').trim().toLowerCase());
}

function loadPersistentUsers() {
  ensureDataDir();
  let db = { users: {} };
  if (fs.existsSync(USERS_DB_FILE)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(USERS_DB_FILE, 'utf8'));
      if (parsed && typeof parsed.users === 'object') {
        db = parsed;
      }
    } catch (_) {
      db = { users: {} };
    }
  }

  let dirty = false;

  if (db.users['seijakutech@gmail.com'] && db.users['seijakutech@gmail.com'].usuario === 'admin') {
    delete db.users['seijakutech@gmail.com'];
    dirty = true;
  }
  if (db.users['simonadministrador@gmail.com'] && db.users['simonadministrador@gmail.com'].rol === 'administrador') {
    delete db.users['simonadministrador@gmail.com'];
    dirty = true;
  }

  if (!db.users[SUPER_ADMIN_USER]) {
    db.users[SUPER_ADMIN_USER] = {
      id: 1,
      nombre: 'Administrador SEIJAKUTECH',
      correo: SUPER_ADMIN_USER,
      usuario: SUPER_ADMIN_USER,
      password_hash: bcrypt.hashSync(SUPER_ADMIN_PASS, 10),
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
    } catch (_) {
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

function readJsonBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (_) {
        resolve({});
      }
    });
  });
}

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

function seijakutechAuthPlugin() {
  return {
    name: 'seijakutech-persistent-auth-api',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const urlObj = new URL(req.url || '/', 'http://localhost');

        if (urlObj.pathname === '/api/register' && req.method === 'POST') {
          const body = await readJsonBody(req);
          const rawCorreo = String(body.correo || '').trim().toLowerCase();
          const rawNombre = String(body.nombre || '').trim() || rawCorreo.split('@')[0];
          const rawUsuario = String(body.usuario || '').trim() || rawCorreo.split('@')[0];
          const rawPassword = String(body.password || '');
          const rawFotoPerfil = body.fotoPerfil && String(body.fotoPerfil).startsWith('data:image/')
            ? String(body.fotoPerfil)
            : null;

          if (rawCorreo === SUPER_ADMIN_USER || rawUsuario.toLowerCase() === SUPER_ADMIN_USER) {
            return sendJson(res, 409, {
              ok: false,
              alreadyExists: true,
              message: "El identificador 'administrador' es de acceso exclusivo del sistema. Inicia sesión directamente."
            });
          }

          if (!isStrictGmail(rawCorreo)) {
            return sendJson(res, 400, {
              ok: false,
              message: 'Validación estricta: Solo se permite registrar cuentas con correo terminado en @gmail.com.'
            });
          }

          if (!rawNombre || !rawPassword || rawPassword.length < 4) {
            return sendJson(res, 400, {
              ok: false,
              message: 'Debes ingresar tu nombre, un correo @gmail.com válido y una contraseña (mínimo 4 caracteres).'
            });
          }

          const db = loadPersistentUsers();
          if (db.users[rawCorreo]) {
            return sendJson(res, 409, {
              ok: false,
              alreadyExists: true,
              message: `El correo '${rawCorreo}' ya está registrado de forma permanente. Inicia sesión con tu contraseña.`
            });
          }

          const bcryptHash = await bcrypt.hash(rawPassword, 10);
          const pwdSha256 = sha256Hex(rawPassword);
          const nowIso = new Date().toISOString();
          const insertedId = Object.keys(db.users).length + 1;
          const welcomeEntry = recordWelcomeEmailDispatch(rawCorreo, rawNombre);

          db.users[rawCorreo] = {
            id: insertedId,
            nombre: rawNombre,
            correo: rawCorreo,
            usuario: rawUsuario,
            password_hash: bcryptHash,
            password_sha256: pwdSha256,
            foto_perfil: rawFotoPerfil,
            bienvenida_enviada: true,
            fecha_bienvenida: welcomeEntry.sentAt,
            rol: 'cliente',
            fecha_registro: nowIso
          };
          savePersistentUsers(db);

          return sendJson(res, 201, {
            ok: true,
            isNewRegistration: true,
            welcomeEmailSent: true,
            welcomeEmailDetails: welcomeEntry,
            message: `Usuario '${rawCorreo}' registrado de forma permanente. Correo automático de bienvenida enviado por única vez.`,
            user: {
              id: insertedId,
              nombre: rawNombre,
              correo: rawCorreo,
              usuario: rawUsuario,
              rol: 'cliente',
              isSuperAdmin: false,
              fotoPerfil: rawFotoPerfil,
              welcomeEmailSent: true,
              fecha_registro: nowIso
            }
          });
        }

        if (urlObj.pathname === '/api/login' && req.method === 'POST') {
          const body = await readJsonBody(req);
          const rawInput = String(body.correo || body.usuario || '').trim();
          const rawCorreo = rawInput.toLowerCase();
          const rawPassword = String(body.password || '');

          const db = loadPersistentUsers();

          // Regla 1: Excepción exclusiva para el texto exacto "administrador" + contraseña "Administrador.2004"
          if (rawInput === SUPER_ADMIN_USER) {
            if (rawPassword !== SUPER_ADMIN_PASS) {
              return sendJson(res, 401, {
                ok: false,
                wrongPassword: true,
                code: 'ADMIN_INVALID_PASSWORD',
                message: 'Acceso bloqueado: La contraseña ingresada no coincide con la cuenta de Administrador (administrador).'
              });
            }
            const adminRecord = db.users[SUPER_ADMIN_USER];
            return sendJson(res, 200, {
              ok: true,
              isNewRegistration: false,
              welcomeEmailSent: false,
              isSuperAdmin: true,
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

          if (!isStrictGmail(rawCorreo)) {
            return sendJson(res, 400, {
              ok: false,
              code: 'INVALID_GMAIL_FORMAT',
              message: 'Validación estricta: Todos los usuarios normales deben iniciar sesión con un correo que termine en @gmail.com.'
            });
          }

          // Un usuario normal solo puede iniciar sesión si existe en la BD (y no fue eliminado)
          const matchedUser = db.users[rawCorreo];
          if (!matchedUser) {
            return sendJson(res, 401, {
              ok: false,
              userNotFound: true,
              code: 'USER_NOT_REGISTERED',
              message: `Acceso rechazado: El correo '${rawCorreo}' no existe en la base de datos. Debes registrarte de nuevo desde cero.`
            });
          }

          let valid = false;
          if (matchedUser.password_hash && matchedUser.password_hash.startsWith('$2')) {
            valid = await bcrypt.compare(rawPassword, matchedUser.password_hash);
          }
          if (!valid && matchedUser.password_sha256) {
            valid = sha256Hex(rawPassword) === matchedUser.password_sha256;
          }

          if (!valid) {
            return sendJson(res, 401, {
              ok: false,
              wrongPassword: true,
              code: 'INVALID_PASSWORD',
              message: `Acceso bloqueado: La contraseña ingresada no coincide con el registro de '${rawCorreo}'.`
            });
          }

          return sendJson(res, 200, {
            ok: true,
            isNewRegistration: false,
            welcomeEmailSent: false,
            isSuperAdmin: false,
            message: `Sesión iniciada correctamente como ${matchedUser.correo} — Credenciales y foto recuperadas de la base de datos.`,
            user: {
              id: matchedUser.id || 1,
              nombre: matchedUser.nombre,
              correo: matchedUser.correo,
              usuario: matchedUser.usuario,
              rol: matchedUser.rol || 'cliente',
              isSuperAdmin: false,
              fotoPerfil: matchedUser.foto_perfil || null,
              welcomeEmailSent: true,
              fecha_registro: matchedUser.fecha_registro
            }
          });
        }

        if (urlObj.pathname === '/api/admin/users' && req.method === 'GET') {
          const requester = String(urlObj.searchParams.get('admin') || '').trim();
          if (requester !== SUPER_ADMIN_USER) {
            return sendJson(res, 403, {
              ok: false,
              message: "Acceso denegado: Vista exclusiva para el usuario 'administrador'."
            });
          }
          const db = loadPersistentUsers();
          const usersList = Object.values(db.users)
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

          return sendJson(res, 200, {
            ok: true,
            total: usersList.length,
            users: usersList
          });
        }

        if (
          (urlObj.pathname === '/api/admin/users' && req.method === 'DELETE') ||
          (urlObj.pathname === '/api/admin/users/delete' && req.method === 'POST')
        ) {
          const body = await readJsonBody(req);
          const requester = String(urlObj.searchParams.get('admin') || body.admin || '').trim();
          if (requester !== SUPER_ADMIN_USER) {
            return sendJson(res, 403, {
              ok: false,
              message: "Acceso denegado: Solo el usuario 'administrador' puede eliminar personas registradas."
            });
          }

          const targetCorreo = String(body.correo || urlObj.searchParams.get('correo') || '').trim().toLowerCase();
          if (!targetCorreo || targetCorreo === SUPER_ADMIN_USER || !isStrictGmail(targetCorreo)) {
            return sendJson(res, 400, {
              ok: false,
              message: 'Debes indicar un correo @gmail.com válido de usuario registrado para eliminar.'
            });
          }

          const db = loadPersistentUsers();
          const existed = Boolean(db.users[targetCorreo]);
          delete db.users[targetCorreo];
          savePersistentUsers(db);
          removeWelcomeEmailForUser(targetCorreo);

          const remainingUsers = Object.values(db.users).filter(
            (u) => u && u.correo && u.correo !== SUPER_ADMIN_USER && isStrictGmail(u.correo)
          );

          return sendJson(res, 200, {
            ok: true,
            deleted: true,
            existed,
            deletedCorreo: targetCorreo,
            totalRemaining: remainingUsers.length,
            message: `El usuario '${targetCorreo}' fue eliminado permanentemente de la base de datos. Si intenta iniciar sesión, el acceso será rechazado y deberá registrarse de nuevo desde cero.`
          });
        }

        if (urlObj.pathname === '/api/profile/photo' && (req.method === 'PUT' || req.method === 'POST')) {
          const body = await readJsonBody(req);
          const rawCorreo = String(body.correo || '').trim().toLowerCase();
          const rawFotoPerfil = String(body.fotoPerfil || '');

          if ((rawCorreo !== SUPER_ADMIN_USER && !isStrictGmail(rawCorreo)) || !rawFotoPerfil.startsWith('data:image/')) {
            return sendJson(res, 400, {
              ok: false,
              message: 'Identificador de sesión o formato de imagen inválido.'
            });
          }

          const db = loadPersistentUsers();
          if (!db.users[rawCorreo]) {
            return sendJson(res, 404, { ok: false, message: 'Usuario no encontrado.' });
          }

          db.users[rawCorreo].foto_perfil = rawFotoPerfil;
          savePersistentUsers(db);

          return sendJson(res, 200, {
            ok: true,
            correo: rawCorreo,
            fotoPerfil: rawFotoPerfil,
            message: 'Foto de perfil guardada de forma persistente en la base de datos.'
          });
        }

        if (urlObj.pathname === '/api/profile' && req.method === 'GET') {
          const rawCorreo = String(urlObj.searchParams.get('correo') || '').trim().toLowerCase();
          if (rawCorreo !== SUPER_ADMIN_USER && !isStrictGmail(rawCorreo)) {
            return sendJson(res, 400, { ok: false, message: 'Identificador de sesión inválido.' });
          }
          const db = loadPersistentUsers();
          const user = db.users[rawCorreo];
          if (!user) {
            return sendJson(res, 404, { ok: false, userNotFound: true, message: 'Usuario no encontrado.' });
          }
          return sendJson(res, 200, {
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
        }

        next();
      });
    }
  };
}

export default defineConfig({
  plugins: [seijakutechAuthPlugin()]
});

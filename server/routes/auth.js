const express = require("express");
const bcrypt = require("bcrypt");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");
const { executeQuery, executeTransaction } = require("../config/database");
const { logSecurityEvent } = require("../utils/security");
const { generateCaptcha, verifyCaptcha } = require("../utils/captcha");
const { validateInput, sanitizeInput } = require("../utils/validation");

const router = express.Router();
const { authenticateToken } = require("../middleware/auth");

// Registro de usuario con validaciones de seguridad
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, captcha } = req.body;

    // Validar captcha
    if (!verifyCaptcha(captcha, req.session.captchaToken)) {
      await logSecurityEvent(
        null,
        "register_attempt",
        "captcha_failed",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(400).json({ error: "Captcha inválido" });
    }

    // Validar entrada
    const validation = validateInput({ username, email, password });
    if (!validation.isValid) {
      return res.status(400).json({ error: validation.errors });
    }

    // Sanitizar entrada
    const sanitizedData = sanitizeInput({ username, email });

    // Verificar si el usuario ya existe
    const existingUser = await executeQuery(
      "SELECT id FROM users WHERE username = ? OR email = ?",
      [sanitizedData.username, sanitizedData.email]
    );

    if (existingUser.length > 0) {
      await logSecurityEvent(
        null,
        "register_attempt",
        "user_exists",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(400).json({ error: "Usuario o email ya existe" });
    }

    // Generar salt y hash de la contraseña
    const saltRounds = Number.parseInt(process.env.BCRYPT_ROUNDS) || 12;
    const salt = await bcrypt.genSalt(saltRounds);
    const passwordHash = await bcrypt.hash(password, salt);

    // Insertar usuario en la base de datos
    const result = await executeQuery(
      "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)",
      [sanitizedData.username, sanitizedData.email, passwordHash, salt]
    );

    // Asignar rol de usuario por defecto
    await executeQuery(
      "INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (?, 3, 1)",
      [result.insertId]
    );

    await logSecurityEvent(
      result.insertId,
      "user_registered",
      "users",
      req.ip,
      req.get("User-Agent"),
      true
    );

    res.status(201).json({
      message: "Usuario registrado exitosamente",
      userId: result.insertId,
    });
  } catch (error) {
    console.error("Error en registro:", error);
    await logSecurityEvent(
      null,
      "register_attempt",
      "system_error",
      req.ip,
      req.get("User-Agent"),
      false
    );
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Login con protección contra fuerza bruta
router.post("/login", async (req, res) => {
  try {
    const { username, password, captcha, twoFactorCode } = req.body;

    // Validar captcha
    if (!verifyCaptcha(captcha, req.session.captchaToken)) {
      await logSecurityEvent(
        null,
        "login_attempt",
        "captcha_failed",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(400).json({ error: "Captcha inválido" });
    }

    // Buscar usuario
    const users = await executeQuery(
      "SELECT id, username, email, password_hash, two_factor_secret, two_factor_enabled, failed_login_attempts, locked_until FROM users WHERE username = ? OR email = ?",
      [username, username]
    );

    if (users.length === 0) {
      await logSecurityEvent(
        null,
        "login_attempt",
        "user_not_found",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    const user = users[0];

    // Verificar si la cuenta está bloqueada
    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      await logSecurityEvent(
        user.id,
        "login_attempt",
        "account_locked",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(423).json({ error: "Cuenta bloqueada temporalmente" });
    }

    // Verificar contraseña
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      // Incrementar intentos fallidos
      const newFailedAttempts = user.failed_login_attempts + 1;
      let lockUntil = null;

      if (newFailedAttempts >= 5) {
        lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutos
      }

      await executeQuery(
        "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
        [newFailedAttempts, lockUntil, user.id]
      );

      await logSecurityEvent(
        user.id,
        "login_attempt",
        "invalid_password",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    // Verificar 2FA si está habilitado
    if (user.two_factor_enabled) {
      if (!twoFactorCode) {
        return res.status(200).json({
          requiresTwoFactor: true,
          message: "Código de autenticación de dos factores requerido",
        });
      }

      const verified = speakeasy.totp.verify({
        secret: user.two_factor_secret,
        encoding: "base32",
        token: twoFactorCode,
        window: 2,
      });

      if (!verified) {
        await logSecurityEvent(
          user.id,
          "login_attempt",
          "invalid_2fa",
          req.ip,
          req.get("User-Agent"),
          false
        );
        return res
          .status(401)
          .json({ error: "Código de autenticación inválido" });
      }
    }

    // Login exitoso - resetear intentos fallidos
    await executeQuery(
      "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = ?",
      [user.id]
    );

    // Crear sesión
    const sessionId = require("crypto").randomBytes(32).toString("hex");
    await executeQuery(
      "INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))",
      [sessionId, user.id, req.ip, req.get("User-Agent")]
    );

    // Generar JWT
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        sessionId: sessionId,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    req.session.userId = user.id;
    req.session.sessionId = sessionId;

    await logSecurityEvent(
      user.id,
      "login_success",
      "authentication",
      req.ip,
      req.get("User-Agent"),
      true
    );

    res.json({
      message: "Login exitoso",
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        twoFactorEnabled: user.two_factor_enabled,
      },
    });
  } catch (error) {
    console.error("Error en login:", error);
    await logSecurityEvent(
      null,
      "login_attempt",
      "system_error",
      req.ip,
      req.get("User-Agent"),
      false
    );
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// Configurar 2FA
router.post("/setup-2fa", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // Generar secreto para 2FA
    const secret = speakeasy.generateSecret({
      name: `${process.env.TWO_FACTOR_SERVICE_NAME} (${req.user.username})`,
      issuer: process.env.TWO_FACTOR_ISSUER,
    });

    // Generar QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Guardar secreto temporalmente (no activar hasta verificar)
    req.session.tempTwoFactorSecret = secret.base32;

    await logSecurityEvent(
      userId,
      "2fa_setup_initiated",
      "authentication",
      req.ip,
      req.get("User-Agent"),
      true
    );

    res.json({
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
    });
  } catch (error) {
    console.error("Error configurando 2FA:", error);
    res
      .status(500)
      .json({ error: "Error configurando autenticación de dos factores" });
  }
});

// Verificar y activar 2FA
router.post("/verify-2fa", authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;
    const tempSecret = req.session.tempTwoFactorSecret;

    if (!tempSecret) {
      return res
        .status(400)
        .json({ error: "No hay configuración de 2FA pendiente" });
    }

    // Verificar token
    const verified = speakeasy.totp.verify({
      secret: tempSecret,
      encoding: "base32",
      token: token,
      window: 2,
    });

    if (!verified) {
      await logSecurityEvent(
        userId,
        "2fa_verification_failed",
        "authentication",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(400).json({ error: "Código de verificación inválido" });
    }

    // Activar 2FA
    await executeQuery(
      "UPDATE users SET two_factor_secret = ?, two_factor_enabled = TRUE WHERE id = ?",
      [tempSecret, userId]
    );

    // Limpiar secreto temporal
    delete req.session.tempTwoFactorSecret;

    await logSecurityEvent(
      userId,
      "2fa_enabled",
      "authentication",
      req.ip,
      req.get("User-Agent"),
      true
    );

    res.json({
      message: "Autenticación de dos factores activada exitosamente",
    });
  } catch (error) {
    console.error("Error verificando 2FA:", error);
    res
      .status(500)
      .json({ error: "Error verificando autenticación de dos factores" });
  }
});

// Desactivar 2FA
router.post("/disable-2fa", authenticateToken, async (req, res) => {
  try {
    const { password, twoFactorCode } = req.body;
    const userId = req.user.id;

    // Verificar contraseña actual
    const users = await executeQuery(
      "SELECT password_hash, two_factor_secret FROM users WHERE id = ?",
      [userId]
    );

    const passwordValid = await bcrypt.compare(
      password,
      users[0].password_hash
    );
    if (!passwordValid) {
      await logSecurityEvent(
        userId,
        "2fa_disable_failed",
        "invalid_password",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // Verificar código 2FA
    const verified = speakeasy.totp.verify({
      secret: users[0].two_factor_secret,
      encoding: "base32",
      token: twoFactorCode,
      window: 2,
    });

    if (!verified) {
      await logSecurityEvent(
        userId,
        "2fa_disable_failed",
        "invalid_2fa",
        req.ip,
        req.get("User-Agent"),
        false
      );
      return res
        .status(401)
        .json({ error: "Código de autenticación inválido" });
    }

    // Desactivar 2FA
    await executeQuery(
      "UPDATE users SET two_factor_secret = NULL, two_factor_enabled = FALSE WHERE id = ?",
      [userId]
    );

    await logSecurityEvent(
      userId,
      "2fa_disabled",
      "authentication",
      req.ip,
      req.get("User-Agent"),
      true
    );

    res.json({ message: "Autenticación de dos factores desactivada" });
  } catch (error) {
    console.error("Error desactivando 2FA:", error);
    res
      .status(500)
      .json({ error: "Error desactivando autenticación de dos factores" });
  }
});

// Logout
router.post("/logout", authenticateToken, async (req, res) => {
  try {
    const sessionId = req.user.sessionId;

    // Invalidar sesión en base de datos
    await executeQuery("UPDATE sessions SET is_active = FALSE WHERE id = ?", [
      sessionId,
    ]);

    // Destruir sesión
    req.session.destroy();

    await logSecurityEvent(
      req.user.id,
      "logout",
      "authentication",
      req.ip,
      req.get("User-Agent"),
      true
    );

    res.json({ message: "Logout exitoso" });
  } catch (error) {
    console.error("Error en logout:", error);
    res.status(500).json({ error: "Error cerrando sesión" });
  }
});

// Generar nuevo captcha
router.get("/captcha", (req, res) => {
  try {
    const captcha = generateCaptcha();
    req.session.captchaToken = captcha.token;

    res.json({
      captcha: captcha.image,
      token: captcha.token,
    });
  } catch (error) {
    console.error("Error generando captcha:", error);
    res.status(500).json({ error: "Error generando captcha" });
  }
});

module.exports = router;

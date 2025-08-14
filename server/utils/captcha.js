const crypto = require("crypto");

// Cache temporal para almacenar captchas (en producción usar Redis)
const captchaStore = new Map();

// Limpiar captchas expirados cada 5 minutos
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of captchaStore.entries()) {
    if (now > value.expires) {
      captchaStore.delete(key);
    }
  }
}, 5 * 60 * 1000);

// Generar captcha matemático simple
function generateCaptcha() {
  const operations = ["+", "-", "*"];
  const operation = operations[Math.floor(Math.random() * operations.length)];
  let num1, num2, answer;

  switch (operation) {
    case "+":
      num1 = Math.floor(Math.random() * 50) + 1;
      num2 = Math.floor(Math.random() * 50) + 1;
      answer = num1 + num2;
      break;
    case "-":
      num1 = Math.floor(Math.random() * 50) + 25;
      num2 = Math.floor(Math.random() * 25) + 1;
      answer = num1 - num2;
      break;
    case "*":
      num1 = Math.floor(Math.random() * 10) + 1;
      num2 = Math.floor(Math.random() * 10) + 1;
      answer = num1 * num2;
      break;
  }

  const question = `${num1} ${operation} ${num2} = ?`;

  // Generar token único para este captcha
  const token = crypto.randomBytes(32).toString("hex");

  // Almacenar en cache temporal (expira en 10 minutos)
  captchaStore.set(token, {
    answer: answer.toString(),
    expires: Date.now() + 10 * 60 * 1000, // 10 minutos
    created: Date.now(),
  });

  console.log(`[CAPTCHA] Generado: ${question} = ${answer}, Token: ${token}`);

  return {
    image: question,
    token: token,
    // No incluir answer en respuesta de producción
    answer: process.env.NODE_ENV !== "production" ? answer : undefined,
  };
}

// Verificar respuesta del captcha
function verifyCaptcha(userAnswer, token) {
  console.log(
    `[CAPTCHA] Verificando: userAnswer="${userAnswer}", token="${token}"`
  );

  if (!userAnswer || !token) {
    console.log("[CAPTCHA] Faltan parámetros");
    return false;
  }

  // Buscar en el cache
  const storedCaptcha = captchaStore.get(token);

  if (!storedCaptcha) {
    console.log("[CAPTCHA] Token no encontrado o expirado");
    return false;
  }

  // Verificar si ha expirado
  if (Date.now() > storedCaptcha.expires) {
    console.log("[CAPTCHA] Token expirado");
    captchaStore.delete(token);
    return false;
  }

  // Comparar respuestas (convertir ambas a string y normalizar)
  const userAnswerStr = userAnswer.toString().trim();
  const correctAnswerStr = storedCaptcha.answer.toString().trim();

  console.log(
    `[CAPTCHA] Comparando: "${userAnswerStr}" === "${correctAnswerStr}"`
  );

  const isValid = userAnswerStr === correctAnswerStr;

  if (isValid) {
    // Eliminar el token una vez usado (un solo uso)
    captchaStore.delete(token);
    console.log("[CAPTCHA] Verificación exitosa");
  } else {
    console.log("[CAPTCHA] Respuesta incorrecta");
  }

  return isValid;
}

// Generar captcha visual más complejo (ASCII art)
function generateVisualCaptcha() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const length = 5;
  let code = "";

  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  // Crear representación ASCII simple
  const asciiArt = createASCIIArt(code);
  const token = crypto.randomBytes(32).toString("hex");

  // Almacenar en cache temporal
  captchaStore.set(token, {
    answer: code,
    expires: Date.now() + 10 * 60 * 1000, // 10 minutos
    created: Date.now(),
  });

  return {
    image: asciiArt,
    token: token,
    code: process.env.NODE_ENV !== "production" ? code : undefined,
  };
}

// Crear arte ASCII simple para el captcha
function createASCIIArt(text) {
  const patterns = {
    A: ["  █  ", " █ █ ", "█████", "█   █", "█   █"],
    B: ["████ ", "█   █", "████ ", "█   █", "████ "],
    C: [" ████", "█    ", "█    ", "█    ", " ████"],
    D: ["████ ", "█   █", "█   █", "█   █", "████ "],
    E: ["█████", "█    ", "███  ", "█    ", "█████"],
    F: ["█████", "█    ", "███  ", "█    ", "█    "],
    G: [" ████", "█    ", "█ ███", "█   █", " ███ "],
    H: ["█   █", "█   █", "█████", "█   █", "█   █"],
    I: [" ███ ", "  █  ", "  █  ", "  █  ", " ███ "],
    J: ["█████", "    █", "    █", "█   █", " ███ "],
    K: ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"],
    L: ["█    ", "█    ", "█    ", "█    ", "█████"],
    M: ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    N: ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    O: [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    P: ["████ ", "█   █", "████ ", "█    ", "█    "],
    Q: [" ███ ", "█   █", "█ █ █", "█  ██", " ████"],
    R: ["████ ", "█   █", "████ ", "█ █  ", "█  █ "],
    S: [" ████", "█    ", " ███ ", "    █", "████ "],
    T: ["█████", "  █  ", "  █  ", "  █  ", "  █  "],
    U: ["█   █", "█   █", "█   █", "█   █", " ███ "],
    V: ["█   █", "█   █", "█   █", " █ █ ", "  █  "],
    W: ["█   █", "█   █", "█ █ █", "██ ██", "█   █"],
    X: ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
    Y: ["█   █", " █ █ ", "  █  ", "  █  ", "  █  "],
    Z: ["█████", "   █ ", "  █  ", " █   ", "█████"],
    0: [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    1: ["  █  ", " ██  ", "  █  ", "  █  ", " ███ "],
    2: [" ███ ", "    █", " ███ ", "█    ", "█████"],
    3: [" ███ ", "    █", " ███ ", "    █", " ███ "],
    4: ["█   █", "█   █", "█████", "    █", "    █"],
    5: ["█████", "█    ", "████ ", "    █", "████ "],
    6: [" ████", "█    ", "████ ", "█   █", " ███ "],
    7: ["█████", "    █", "   █ ", "  █  ", " █   "],
    8: [" ███ ", "█   █", " ███ ", "█   █", " ███ "],
    9: [" ███ ", "█   █", " ████", "    █", " ███ "],
  };

  const result = [];
  for (let row = 0; row < 5; row++) {
    let line = "";
    for (const char of text) {
      if (patterns[char]) {
        line += patterns[char][row] + " ";
      } else {
        line += "     " + " "; // Espacio para caracteres no definidos
      }
    }
    result.push(line);
  }

  return result.join("\n");
}

// Función para limpiar manualmente captchas expirados
function cleanupExpiredCaptchas() {
  const now = Date.now();
  let cleaned = 0;

  for (const [key, value] of captchaStore.entries()) {
    if (now > value.expires) {
      captchaStore.delete(key);
      cleaned++;
    }
  }

  console.log(`[CAPTCHA] Limpieza: ${cleaned} captchas expirados eliminados`);
  return cleaned;
}

// Función para obtener estadísticas del cache
function getCaptchaStats() {
  const now = Date.now();
  let active = 0;
  let expired = 0;

  for (const [key, value] of captchaStore.entries()) {
    if (now > value.expires) {
      expired++;
    } else {
      active++;
    }
  }

  return {
    total: captchaStore.size,
    active,
    expired,
  };
}

module.exports = {
  generateCaptcha,
  verifyCaptcha,
  generateVisualCaptcha,
  cleanupExpiredCaptchas,
  getCaptchaStats,
};

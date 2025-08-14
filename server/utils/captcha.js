const crypto = require("crypto")

// Generar captcha matemático simple
function generateCaptcha() {
  const operations = ["+", "-", "*"]
  const operation = operations[Math.floor(Math.random() * operations.length)]

  let num1, num2, answer

  switch (operation) {
    case "+":
      num1 = Math.floor(Math.random() * 50) + 1
      num2 = Math.floor(Math.random() * 50) + 1
      answer = num1 + num2
      break
    case "-":
      num1 = Math.floor(Math.random() * 50) + 25
      num2 = Math.floor(Math.random() * 25) + 1
      answer = num1 - num2
      break
    case "*":
      num1 = Math.floor(Math.random() * 10) + 1
      num2 = Math.floor(Math.random() * 10) + 1
      answer = num1 * num2
      break
  }

  const question = `${num1} ${operation} ${num2} = ?`

  // Generar token único para este captcha
  const token = crypto.randomBytes(16).toString("hex")

  // En un entorno real, almacenarías esto en Redis o similar
  // Por simplicidad, usamos el hash del answer + token
  const hash = crypto.createHash("sha256").update(`${answer}:${token}`).digest("hex")

  return {
    image: question,
    token: hash,
    answer: answer, // Solo para desarrollo, no enviar al cliente
  }
}

// Verificar respuesta del captcha
function verifyCaptcha(userAnswer, token) {
  if (!userAnswer || !token) {
    return false
  }

  // En un entorno real, verificarías contra el almacén temporal
  // Por simplicidad, reconstruimos el hash
  try {
    const hash = crypto
      .createHash("sha256")
      .update(`${userAnswer}:${token.split(":")[1] || ""}`)
      .digest("hex")
    return hash === token.split(":")[0]
  } catch (error) {
    return false
  }
}

// Generar captcha visual más complejo (ASCII art)
function generateVisualCaptcha() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  const length = 5
  let code = ""

  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length))
  }

  // Crear representación ASCII simple
  const asciiArt = createASCIIArt(code)
  const token = crypto.randomBytes(16).toString("hex")
  const hash = crypto.createHash("sha256").update(`${code}:${token}`).digest("hex")

  return {
    image: asciiArt,
    token: `${hash}:${token}`,
    code: code, // Solo para desarrollo
  }
}

// Crear arte ASCII simple para el captcha
function createASCIIArt(text) {
  const patterns = {
    A: ["  █  ", " █ █ ", "█████", "█   █", "█   █"],
    B: ["████ ", "█   █", "████ ", "█   █", "████ "],
    C: [" ████", "█    ", "█    ", "█    ", " ████"],
    D: ["████ ", "█   █", "█   █", "█   █", "████ "],
    E: ["█████", "█    ", "███  ", "█    ", "█████"],
    // ... más patrones según necesidad
    0: [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    1: ["  █  ", " ██  ", "  █  ", "  █  ", " ███ "],
    2: [" ███ ", "    █", " ███ ", "█    ", "█████"],
    3: [" ███ ", "    █", " ███ ", "    █", " ███ "],
    4: ["█   █", "█   █", "█████", "    █", "    █"],
    5: ["█████", "█    ", "████ ", "    █", "████ "],
    // ... más números
  }

  const result = []
  for (let row = 0; row < 5; row++) {
    let line = ""
    for (const char of text) {
      if (patterns[char]) {
        line += patterns[char][row] + " "
      } else {
        line += "     " + " " // Espacio para caracteres no definidos
      }
    }
    result.push(line)
  }

  return result.join("\n")
}

module.exports = {
  generateCaptcha,
  verifyCaptcha,
  generateVisualCaptcha,
}

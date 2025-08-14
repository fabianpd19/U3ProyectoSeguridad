// Lógica específica para la página de login

const Auth = {
  async getCaptcha() {
    // Simulación de obtención de captcha
    return { captcha: "ABC123", token: "token123" };
  },
  async login(credentials) {
    // Simulación de login
    if (credentials.captcha !== "ABC123") throw new Error("Captcha incorrecto");
    if (
      credentials.username === "admin" &&
      credentials.password === "password"
    ) {
      if (credentials.twoFactorCode === "123456") return { success: true };
      else return { success: false, requiresTwoFactor: true };
    }
    throw new Error("Credenciales incorrectas");
  },
  async register(userData) {
    // Simulación de registro
    if (userData.captcha !== "token123") throw new Error("Captcha incorrecto");
    if (userData.password !== userData.confirmPassword)
      throw new Error("Las contraseñas no coinciden");
    if (!userData.username || !userData.email || !userData.password)
      throw new Error("Por favor completa todos los campos");
    return { success: true };
  },
};

// ...existing code...

document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  const loginLink = document.getElementById("loginLink");
  const registerLink = document.getElementById("registerLink");
  const captchaDisplay = document.getElementById("captchaDisplay");
  const refreshCaptcha = document.getElementById("refreshCaptcha");
  const regCaptchaDisplay = document.getElementById("regCaptchaDisplay");
  const regRefreshCaptcha = document.getElementById("regRefreshCaptcha");
  const passwordInput = document.getElementById("regPassword");
  const strengthBar = document.getElementById("passwordStrength");
  const strengthText = document.getElementById("strengthText");

  let currentCaptcha = null;
  let currentRegCaptcha = null;
  let requiresTwoFactor = false;

  // Cargar captcha inicial
  loadCaptcha();
  loadRegCaptcha();

  // Event listeners
  loginForm.addEventListener("submit", handleLogin);
  registerForm.addEventListener("submit", handleRegister);
  loginLink.addEventListener("click", showLoginForm);
  registerLink.addEventListener("click", showRegisterForm);
  refreshCaptcha.addEventListener("click", loadCaptcha);
  regRefreshCaptcha.addEventListener("click", loadRegCaptcha);
  passwordInput.addEventListener("input", updatePasswordStrength);

  // Funciones de captcha
  async function loadCaptcha() {
    try {
      const captcha = await Auth.getCaptcha();
      captchaDisplay.textContent = captcha.captcha;
      currentCaptcha = captcha.token;
    } catch (error) {
      captchaDisplay.textContent = "Error cargando captcha";
      console.error("Error loading captcha:", error);
    }
  }

  async function loadRegCaptcha() {
    try {
      const captcha = await Auth.getCaptcha();
      regCaptchaDisplay.textContent = captcha.captcha;
      currentRegCaptcha = captcha.token;
    } catch (error) {
      regCaptchaDisplay.textContent = "Error cargando captcha";
      console.error("Error loading register captcha:", error);
    }
  }

  // Manejo del login
  async function handleLogin(e) {
    e.preventDefault();

    const loginBtn = document.getElementById("loginBtn");
    const formData = new FormData(loginForm);

    const credentials = {
      username: formData.get("username"),
      password: formData.get("password"),
      captcha: formData.get("captcha"),
      twoFactorCode: formData.get("twoFactorCode"),
    };

    // Validaciones básicas
    if (
      !credentials.username ||
      !credentials.password ||
      !credentials.captcha
    ) {
      UI.showAlert("Por favor completa todos los campos requeridos", "error");
      return;
    }

    if (requiresTwoFactor && !credentials.twoFactorCode) {
      UI.showAlert(
        "Por favor ingresa el código de autenticación de dos factores",
        "error"
      );
      return;
    }

    try {
      UI.setLoading(loginBtn, true);

      const result = await Auth.login(credentials);

      if (result.requiresTwoFactor) {
        requiresTwoFactor = true;
        document.getElementById("twoFactorGroup").style.display = "block";
        UI.showAlert(
          "Por favor ingresa tu código de autenticación de dos factores",
          "info"
        );
        return;
      }

      if (result.success) {
        UI.showAlert("Login exitoso. Redirigiendo...", "success");
        setTimeout(() => {
          window.location.href = "/dashboard.html";
        }, 1000);
      }
    } catch (error) {
      UI.showAlert(error.message || "Error durante el login", "error");
      loadCaptcha(); // Recargar captcha después de error
      requiresTwoFactor = false;
      document.getElementById("twoFactorGroup").style.display = "none";
    } finally {
      UI.setLoading(loginBtn, false);
    }
  }

  // Manejo del registro
  async function handleRegister(e) {
    e.preventDefault();

    const registerBtn = document.getElementById("registerBtn");
    const formData = new FormData(registerForm);

    const userData = {
      username: formData.get("regUsername"),
      email: formData.get("regEmail"),
      password: formData.get("regPassword"),
      confirmPassword: formData.get("regConfirmPassword"),
      captcha: formData.get("regCaptcha"),
      captchaToken: currentRegCaptcha,
    };

    // Validaciones
    if (
      !userData.username ||
      !userData.email ||
      !userData.password ||
      !userData.captcha
    ) {
      UI.showAlert("Por favor completa todos los campos", "error");
      return;
    }

    if (userData.password !== userData.confirmPassword) {
      UI.showAlert("Las contraseñas no coinciden", "error");
      return;
    }

    if (!isValidPassword(userData.password)) {
      UI.showAlert(
        "La contraseña no cumple con los requisitos de seguridad",
        "error"
      );
      return;
    }

    try {
      UI.setLoading(registerBtn, true);

      const result = await Auth.register(userData);

      if (result.success) {
        UI.showAlert(
          "Registro exitoso. Por favor verifica tu email.",
          "success"
        );
        showLoginForm();
        registerForm.reset();
      }
    } catch (error) {
      UI.showAlert(error.message || "Error durante el registro", "error");
      loadRegCaptcha();
    } finally {
      UI.setLoading(registerBtn, false);
    }
  }

  // Funciones de UI
  function showLoginForm() {
    document.getElementById("loginContainer").style.display = "block";
    document.getElementById("registerContainer").style.display = "none";
    requiresTwoFactor = false;
    document.getElementById("twoFactorGroup").style.display = "none";
  }

  function showRegisterForm() {
    document.getElementById("loginContainer").style.display = "none";
    document.getElementById("registerContainer").style.display = "block";
  }

  // Validación de contraseña
  function isValidPassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return (
      password.length >= minLength &&
      hasUpperCase &&
      hasLowerCase &&
      hasNumbers &&
      hasSpecialChar
    );
  }

  // Medidor de fuerza de contraseña
  function updatePasswordStrength() {
    const password = passwordInput.value;
    let strength = 0;
    const feedback = [];

    if (password.length >= 8) strength++;
    else feedback.push("mínimo 8 caracteres");

    if (/[A-Z]/.test(password)) strength++;
    else feedback.push("mayúsculas");

    if (/[a-z]/.test(password)) strength++;
    else feedback.push("minúsculas");

    if (/\d/.test(password)) strength++;
    else feedback.push("números");

    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength++;
    else feedback.push("símbolos");

    // Actualizar barra visual
    const percentage = (strength / 5) * 100;
    strengthBar.style.width = percentage + "%";

    if (strength <= 2) {
      strengthBar.className = "strength-bar weak";
      strengthText.textContent = "Débil - Falta: " + feedback.join(", ");
    } else if (strength <= 3) {
      strengthBar.className = "strength-bar medium";
      strengthText.textContent = "Media - Falta: " + feedback.join(", ");
    } else if (strength <= 4) {
      strengthBar.className = "strength-bar strong";
      strengthText.textContent = "Fuerte - Falta: " + feedback.join(", ");
    } else {
      strengthBar.className = "strength-bar very-strong";
      strengthText.textContent = "Muy fuerte";
    }
  }
});

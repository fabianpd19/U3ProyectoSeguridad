// Lógica específica para la página de login
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
  if (loginForm) loginForm.addEventListener("submit", handleLogin);
  if (registerForm) registerForm.addEventListener("submit", handleRegister);
  if (loginLink) loginLink.addEventListener("click", showLoginForm);
  if (registerLink) registerLink.addEventListener("click", showRegisterForm);
  if (refreshCaptcha) refreshCaptcha.addEventListener("click", loadCaptcha);
  if (regRefreshCaptcha)
    regRefreshCaptcha.addEventListener("click", loadRegCaptcha);
  if (passwordInput)
    passwordInput.addEventListener("input", updatePasswordStrength);

  // Funciones de captcha
  async function loadCaptcha() {
    try {
      if (captchaDisplay) captchaDisplay.textContent = "Cargando...";
      const captcha = await window.AuthManager.getCaptcha();
      if (captchaDisplay) captchaDisplay.textContent = captcha.captcha;
      currentCaptcha = captcha.token;
    } catch (error) {
      if (captchaDisplay) captchaDisplay.textContent = "Error cargando captcha";
      console.error("Error loading captcha:", error);
      window.UI.showAlert(
        "Error al cargar el captcha. Intenta nuevamente.",
        "error"
      );
    }
  }

  async function loadRegCaptcha() {
    try {
      if (regCaptchaDisplay) regCaptchaDisplay.textContent = "Cargando...";
      const captcha = await window.AuthManager.getCaptcha();
      if (regCaptchaDisplay) regCaptchaDisplay.textContent = captcha.captcha;
      currentRegCaptcha = captcha.token;
    } catch (error) {
      if (regCaptchaDisplay)
        regCaptchaDisplay.textContent = "Error cargando captcha";
      console.error("Error loading register captcha:", error);
      window.UI.showAlert(
        "Error al cargar el captcha de registro. Intenta nuevamente.",
        "error"
      );
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
      captchaToken: currentCaptcha, // Token del servidor
      twoFactorCode: formData.get("twoFactorCode"),
    };

    // Validaciones básicas
    if (
      !credentials.username ||
      !credentials.password ||
      !credentials.captcha
    ) {
      window.UI.showAlert(
        "Por favor completa todos los campos requeridos",
        "error"
      );
      return;
    }

    if (requiresTwoFactor && !credentials.twoFactorCode) {
      window.UI.showAlert(
        "Por favor ingresa el código de autenticación de dos factores",
        "error"
      );
      return;
    }

    if (!currentCaptcha) {
      window.UI.showAlert(
        "Error con el captcha. Por favor recarga la página.",
        "error"
      );
      return;
    }

    try {
      window.UI.setLoading(loginBtn, true);
      const result = await window.AuthManager.login(credentials);

      if (result.requiresTwoFactor) {
        requiresTwoFactor = true;
        const twoFactorGroup = document.getElementById("twoFactorGroup");
        if (twoFactorGroup) twoFactorGroup.style.display = "block";
        window.UI.showAlert(
          "Por favor ingresa tu código de autenticación de dos factores",
          "info"
        );
        return;
      }

      if (result.success && result.token) {
        window.UI.showAlert("Login exitoso. Redirigiendo...", "success");
        setTimeout(() => {
          window.location.href = "/frontend/dashboard.html";
        }, 1000);
      } else {
        window.UI.showAlert(
          result.error || "Error desconocido durante el login",
          "error"
        );
        await loadCaptcha(); // Recargar captcha después de error
      }
    } catch (error) {
      console.error("Login error:", error);
      window.UI.showAlert(
        error.message || "Error durante el login. Verifica tus credenciales.",
        "error"
      );
      await loadCaptcha(); // Recargar captcha después de error
      requiresTwoFactor = false;
      const twoFactorGroup = document.getElementById("twoFactorGroup");
      if (twoFactorGroup) twoFactorGroup.style.display = "none";
    } finally {
      window.UI.setLoading(loginBtn, false);
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
      confirmPassword:
        document.getElementById("regConfirmPassword")?.value ||
        formData.get("regPassword"),
      captcha: formData.get("regCaptcha"),
      captchaToken: currentRegCaptcha, // Token del servidor
    };

    // Validaciones
    if (
      !userData.username ||
      !userData.email ||
      !userData.password ||
      !userData.captcha
    ) {
      window.UI.showAlert("Por favor completa todos los campos", "error");
      return;
    }

    if (userData.password !== userData.confirmPassword) {
      window.UI.showAlert("Las contraseñas no coinciden", "error");
      return;
    }

    if (!currentRegCaptcha) {
      window.UI.showAlert(
        "Error con el captcha. Por favor recarga la página.",
        "error"
      );
      return;
    }

    // Validaciones usando la utilidad global si está disponible
    if (window.Validation) {
      const passwordValidation = window.Validation.password(userData.password);
      if (!passwordValidation.isValid) {
        window.UI.showAlert(
          "Contraseña inválida: " + passwordValidation.errors.join(", "),
          "error"
        );
        return;
      }

      const usernameValidation = window.Validation.username(userData.username);
      if (!usernameValidation.isValid) {
        window.UI.showAlert(
          "Usuario inválido: " + usernameValidation.errors.join(", "),
          "error"
        );
        return;
      }

      if (!window.Validation.email(userData.email)) {
        window.UI.showAlert("Email inválido", "error");
        return;
      }
    }

    try {
      window.UI.setLoading(registerBtn, true);
      const result = await window.AuthManager.register(userData);

      if (result.success || result.userId) {
        window.UI.showAlert(
          "Registro exitoso. Ahora puedes iniciar sesión.",
          "success"
        );
        showLoginForm();
        registerForm.reset();
        updatePasswordStrength(); // Reset password strength indicator
      } else {
        window.UI.showAlert(
          result.error || "Error durante el registro",
          "error"
        );
        await loadRegCaptcha();
      }
    } catch (error) {
      console.error("Register error:", error);
      window.UI.showAlert(
        error.message || "Error durante el registro. Intenta nuevamente.",
        "error"
      );
      await loadRegCaptcha();
    } finally {
      window.UI.setLoading(registerBtn, false);
    }
  }

  // Funciones de UI
  function showLoginForm() {
    const loginContainer = document.getElementById("loginContainer");
    const registerContainer = document.getElementById("registerContainer");
    const twoFactorGroup = document.getElementById("twoFactorGroup");

    if (loginContainer) loginContainer.style.display = "block";
    if (registerContainer) registerContainer.style.display = "none";
    if (loginForm && loginForm.parentElement)
      loginForm.parentElement.style.display = "block";
    if (registerForm) registerForm.style.display = "none";

    requiresTwoFactor = false;
    if (twoFactorGroup) twoFactorGroup.style.display = "none";
  }

  function showRegisterForm() {
    const loginContainer = document.getElementById("loginContainer");
    const registerContainer = document.getElementById("registerContainer");

    if (loginForm && loginForm.parentElement)
      loginForm.parentElement.style.display = "none";
    if (registerForm) registerForm.style.display = "block";
    if (loginContainer) loginContainer.style.display = "none";
    if (registerContainer) registerContainer.style.display = "block";
  }

  function updatePasswordStrength() {
    if (!passwordInput || !strengthBar || !strengthText) return;

    const password = passwordInput.value;
    if (!password) {
      strengthBar.style.width = "0%";
      strengthBar.className = "strength-bar";
      strengthText.textContent = "";
      return;
    }

    // Validación básica si no hay utilidad global
    let validation = { strength: "media", isValid: true, errors: [] };

    if (window.Validation) {
      validation = window.Validation.password(password);
    } else {
      // Validación básica sin utilidad
      if (password.length < 8) {
        validation = {
          strength: "débil",
          isValid: false,
          errors: ["mínimo 8 caracteres"],
        };
      } else if (
        password.length >= 12 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /\d/.test(password) &&
        /[!@#$%^&*]/.test(password)
      ) {
        validation = { strength: "muy fuerte", isValid: true, errors: [] };
      } else if (
        password.length >= 10 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /\d/.test(password)
      ) {
        validation = { strength: "fuerte", isValid: true, errors: [] };
      }
    }

    const strengthLevels = [
      "muy débil",
      "débil",
      "media",
      "fuerte",
      "muy fuerte",
    ];
    const strengthIndex = strengthLevels.indexOf(validation.strength);
    const percentage = Math.max(((strengthIndex + 1) / 5) * 100, 20);

    strengthBar.style.width = percentage + "%";

    if (strengthIndex <= 1) {
      strengthBar.className = "strength-bar weak";
    } else if (strengthIndex === 2) {
      strengthBar.className = "strength-bar medium";
    } else if (strengthIndex === 3) {
      strengthBar.className = "strength-bar strong";
    } else {
      strengthBar.className = "strength-bar very-strong";
    }

    if (validation.isValid) {
      strengthText.textContent = `Contraseña ${validation.strength}`;
      strengthText.className = "strength-text success";
    } else {
      strengthText.textContent = `${
        validation.strength
      } - Falta: ${validation.errors.join(", ")}`;
      strengthText.className = "strength-text error";
    }
  }
});

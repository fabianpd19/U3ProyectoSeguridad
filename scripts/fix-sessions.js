const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");

async function fixSessions() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST || "127.0.0.1", // mejor usar 127.0.0.1 en vez de localhost
    port: process.env.DB_PORT || 3307,
    user: process.env.DB_USER || "secure_user",
    password: process.env.DB_PASSWORD || "secure_pass_2024",
  });

  try {
    console.log("🔧 Arreglando tabla de sesiones...");

    // Leer y ejecutar el script SQL
    const sqlScript = fs.readFileSync(
      path.join(__dirname, "../database/fix_sessions.sql"),
      "utf8"
    );
    const statements = sqlScript.split(";").filter((stmt) => stmt.trim());

    for (const statement of statements) {
      if (statement.trim()) {
        await connection.execute(statement);
        console.log("✅ Ejecutado:", statement.substring(0, 50) + "...");
      }
    }

    console.log("✅ Tabla de sesiones arreglada correctamente");
    console.log('📝 La tabla original se renombró a "user_sessions"');
    console.log('🆕 Nueva tabla "sessions" creada para express-mysql-session');
  } catch (error) {
    console.error("❌ Error arreglando sesiones:", error.message);
    process.exit(1);
  } finally {
    await connection.end();
  }
}

fixSessions();

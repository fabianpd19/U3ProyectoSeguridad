const mysql = require("mysql2/promise");
const fs = require("fs").promises;
const path = require("path");

async function setupDatabase() {
  console.log("🔧 Configurando base de datos...");

  try {
    // Conectar a MySQL
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || "127.0.0.1", // mejor usar 127.0.0.1 en vez de localhost
      port: process.env.DB_PORT || 3307,
      user: process.env.DB_USER || "secure_user",
      password: process.env.DB_PASSWORD || "secure_pass_2024",
    });

    // Crear base de datos si no existe
    await connection.query(
      `CREATE DATABASE IF NOT EXISTS ${
        process.env.DB_NAME || "secure_platform"
      }`
    );
    await connection.query(`USE ${process.env.DB_NAME || "secure_platform"}`);

    // Ejecutar scripts SQL
    const schemaPath = path.join(__dirname, "../database/schema.sql");
    const schema = await fs.readFile(schemaPath, "utf8");

    const statements = schema.split(";").filter((stmt) => stmt.trim());
    for (const statement of statements) {
      if (statement.trim()) {
        await connection.execute(statement);
      }
    }

    console.log("✅ Base de datos configurada correctamente");
    await connection.end();
  } catch (error) {
    console.error("❌ Error configurando base de datos:", error.message);
    process.exit(1);
  }
}

async function createDirectories() {
  console.log("📁 Creando directorios necesarios...");

  const directories = ["logs", "certs", "uploads", "temp"];

  for (const dir of directories) {
    try {
      await fs.mkdir(dir, { recursive: true });
      console.log(`✅ Directorio creado: ${dir}`);
    } catch (error) {
      console.log(`ℹ️  Directorio ya existe: ${dir}`);
    }
  }
}

async function generateSecrets() {
  console.log("🔐 Generando secretos de seguridad...");

  const crypto = require("crypto");

  const secrets = {
    SESSION_SECRET: crypto.randomBytes(64).toString("hex"),
    JWT_SECRET: crypto.randomBytes(64).toString("hex"),
    ENCRYPTION_KEY: crypto.randomBytes(32).toString("hex"),
  };

  console.log("🔑 Secretos generados (agregar al archivo .env):");
  for (const [key, value] of Object.entries(secrets)) {
    console.log(`${key}=${value}`);
  }
}

async function main() {
  console.log("🚀 Iniciando configuración de Plataforma Web Segura...\n");

  await createDirectories();
  await setupDatabase();
  await generateSecrets();

  console.log("\n✅ Configuración completada exitosamente!");
  console.log("📝 No olvides:");
  console.log("   1. Actualizar el archivo .env con los secretos generados");
  console.log("   2. Generar certificados SSL");
  console.log("   3. Ejecutar npm run db:seed para datos iniciales");
}

if (require.main === module) {
  main().catch(console.error);
}

const mysql = require("mysql2/promise");
const fs = require("fs").promises;
const path = require("path");
require("dotenv").config();

class DatabaseMigrator {
  constructor() {
    this.connection = null;
    this.migrationFiles = [
      "schema.sql",
      "abac_schema.sql",
      "security_extensions.sql",
    ];
  }

  async connect() {
    try {
      this.connection = await mysql.createConnection({
        host: process.env.DB_HOST || "localhost",
        port: process.env.DB_PORT || 3307,
        user: process.env.DB_USER || "root",
        password: process.env.DB_PASSWORD || "",
        multipleStatements: true,
      });

      console.log("✅ Connected to MySQL server");

      // Create database if it doesn't exist
      await this.connection.execute(
        `CREATE DATABASE IF NOT EXISTS \`${
          process.env.DB_NAME || "secure_platform"
        }\``
      );
      await this.connection.execute(
        `USE \`${process.env.DB_NAME || "secure_platform"}\``
      );

      console.log(
        `✅ Database '${process.env.DB_NAME || "secure_platform"}' ready`
      );
    } catch (error) {
      console.error("❌ Database connection failed:", error.message);
      process.exit(1);
    }
  }

  async createMigrationsTable() {
    const createTableSQL = `
            CREATE TABLE IF NOT EXISTS migrations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL UNIQUE,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                checksum VARCHAR(64) NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        `;

    await this.connection.execute(createTableSQL);
    console.log("✅ Migrations table ready");
  }

  async getExecutedMigrations() {
    const [rows] = await this.connection.execute(
      "SELECT filename, checksum FROM migrations"
    );
    return new Map(rows.map((row) => [row.filename, row.checksum]));
  }

  async calculateChecksum(content) {
    const crypto = require("crypto");
    return crypto.createHash("sha256").update(content).digest("hex");
  }

  async executeMigration(filename) {
    const filePath = path.join(__dirname, "..", "database", filename);

    try {
      const content = await fs.readFile(filePath, "utf8");
      const checksum = await this.calculateChecksum(content);

      console.log(`📄 Executing migration: ${filename}`);

      // Split SQL content by semicolons and execute each statement
      const statements = content
        .split(";")
        .map((stmt) => stmt.trim())
        .filter((stmt) => stmt.length > 0);

      for (const statement of statements) {
        if (statement.trim()) {
          await this.connection.execute(statement);
        }
      }

      // Record migration as executed
      await this.connection.execute(
        "INSERT INTO migrations (filename, checksum) VALUES (?, ?) ON DUPLICATE KEY UPDATE checksum = VALUES(checksum), executed_at = CURRENT_TIMESTAMP",
        [filename, checksum]
      );

      console.log(`✅ Migration completed: ${filename}`);
      return true;
    } catch (error) {
      console.error(`❌ Migration failed: ${filename}`, error.message);
      return false;
    }
  }

  async runMigrations() {
    console.log("🚀 Starting database migrations...\n");

    await this.createMigrationsTable();
    const executedMigrations = await this.getExecutedMigrations();

    let successCount = 0;
    let failCount = 0;

    for (const filename of this.migrationFiles) {
      const filePath = path.join(__dirname, "..", "database", filename);

      try {
        await fs.access(filePath);

        // Check if migration needs to run
        const content = await fs.readFile(filePath, "utf8");
        const currentChecksum = await this.calculateChecksum(content);
        const executedChecksum = executedMigrations.get(filename);

        if (executedChecksum && executedChecksum === currentChecksum) {
          console.log(`⏭️  Skipping (already executed): ${filename}`);
          continue;
        }

        if (executedChecksum && executedChecksum !== currentChecksum) {
          console.log(`🔄 Re-running (content changed): ${filename}`);
        }

        const success = await this.executeMigration(filename);
        if (success) {
          successCount++;
        } else {
          failCount++;
        }
      } catch (error) {
        if (error.code === "ENOENT") {
          console.log(`⚠️  Migration file not found: ${filename}`);
        } else {
          console.error(`❌ Error processing ${filename}:`, error.message);
          failCount++;
        }
      }
    }

    console.log("\n📊 Migration Summary:");
    console.log(`✅ Successful: ${successCount}`);
    console.log(`❌ Failed: ${failCount}`);
    console.log(
      `⏭️  Skipped: ${this.migrationFiles.length - successCount - failCount}`
    );

    if (failCount > 0) {
      console.log(
        "\n⚠️  Some migrations failed. Please check the errors above."
      );
      process.exit(1);
    } else {
      console.log("\n🎉 All migrations completed successfully!");
    }
  }

  async close() {
    if (this.connection) {
      await this.connection.end();
      console.log("✅ Database connection closed");
    }
  }
}

// Main execution
async function main() {
  const migrator = new DatabaseMigrator();

  try {
    await migrator.connect();
    await migrator.runMigrations();
  } catch (error) {
    console.error("❌ Migration process failed:", error.message);
    process.exit(1);
  } finally {
    await migrator.close();
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = DatabaseMigrator;

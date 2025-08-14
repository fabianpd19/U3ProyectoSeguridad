// scripts/seed.js
require("dotenv").config();
const fs = require("fs");
const mysql = require("mysql2/promise");

(async () => {
  console.log("🌱 Starting database seeding...");

  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    multipleStatements: true, // IMPORTANTE para ejecutar todo el seed.sql
  });

  console.log("✅ Connected to database");

  try {
    const seedSql = fs.readFileSync("./database/seed.sql", "utf8");

    console.log("📝 Executing seed data...");
    await connection.query(seedSql);

    console.log("🎉 Database seeded successfully!");
  } catch (err) {
    console.error("❌ Error during seeding:", err);
  } finally {
    await connection.end();
    console.log("🔌 Database connection closed");
  }
})();

const express = require("express");
const router = express.Router();

// GET /api/users - Listar usuarios
router.get("/", async (req, res) => {
  // Implementar listado de usuarios
});

// GET /api/users/:id - Obtener usuario
router.get("/:id", async (req, res) => {
  // Implementar obtener usuario por ID
});

module.exports = router;

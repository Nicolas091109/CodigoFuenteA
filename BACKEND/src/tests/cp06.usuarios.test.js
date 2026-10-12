const express = require("express");
const request = require("supertest");

jest.mock("../src/db", () => ({
  pool: {
    query: jest.fn()
  }
}));

const { pool } = require("../src/db");
const usersRouter = require("../src/routes/users");

const app = express();
app.use(express.json());
app.use("/usuarios", usersRouter);

beforeEach(() => {
  jest.clearAllMocks();
});

test("CP-06: la contraseña debe almacenarse como hash bcrypt", async () => {
  const contrasena = "ClaveSegura.2026!";

  pool.query.mockResolvedValueOnce({
    rows: [{
      id: 100,
      nombre_usuario: "cp06_prueba"
    }]
  });

  const respuesta = await request(app)
    .post("/usuarios")
    .send({
      nombre_usuario: "cp06_prueba",
      contrasena_hash: contrasena,
      correo: "cp06.prueba@example.test"
    });

  expect(respuesta.status).toBe(201);
  expect(pool.query).toHaveBeenCalledTimes(1);

  const [consulta, parametros] = pool.query.mock.calls[0];

  expect(consulta).toContain("INSERT INTO usuarios");

  expect(parametros[1]).not.toBe(contrasena);

  expect(parametros[1]).toMatch(/^\$2[aby]\$\d{2}\$/);
});

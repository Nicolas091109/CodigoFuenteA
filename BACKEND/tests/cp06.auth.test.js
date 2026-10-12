const express = require("express");
const request = require("supertest");
const bcrypt = require("bcryptjs");

jest.mock("../src/db", () => ({
  pool: {
    query: jest.fn()
  }
}));

const { pool } = require("../src/db");
const authRouter = require("../src/routes/auth");

const app = express();
app.use(express.json());
app.use("/autenticacion", authRouter);

jest.setTimeout(15000);

beforeEach(() => {
  jest.clearAllMocks();
});

test("CP-06: prevenir SQL Injection mediante consulta parametrizada", async () => {
  const payload = "' OR '1'='1' --";

  pool.query.mockResolvedValueOnce({
    rows: []
  });

  const respuesta = await request(app)
    .post("/autenticacion/login")
    .send({
      nombre_usuario: payload,
      password: "ClaveSegura.2026!"
    });

  expect(respuesta.status).toBe(401);

  expect(respuesta.body).not.toHaveProperty("token");

  expect(pool.query).toHaveBeenCalledTimes(1);

  const [consulta, parametros] = pool.query.mock.calls[0];

  expect(consulta).toContain("WHERE nombre_usuario = $1");

  expect(consulta).not.toContain(payload);

  expect(parametros).toEqual([payload]);
});


test("CP-06: validar contraseña almacenada con bcrypt", async () => {
  const password = "ClaveSegura.2026!";

  const passwordHash = await bcrypt.hash(password, 4);

  pool.query
    .mockResolvedValueOnce({
      rows: [{
        id: 100,
        nombre_usuario: "cp06_prueba",
        contrasena_hash: passwordHash
      }]
    })
    .mockResolvedValueOnce({
      rows: [{
        id: 1,
        empresa_id: 2
      }]
    })
    .mockResolvedValueOnce({
      rows: []
    });

  const respuesta = await request(app)
    .post("/autenticacion/login")
    .send({
      nombre_usuario: "cp06_prueba",
      password: password
    });

  expect(respuesta.status).toBe(200);

  expect(respuesta.body).toHaveProperty("token");
});


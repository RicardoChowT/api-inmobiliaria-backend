require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();
const port = process.env.PORT || 3001;

// Configuración de CORS para producción y desarrollo
if (process.env.NODE_ENV === "production") {
  // Configuración para PRODUCCIÓN
  const allowedOrigins = [
    "http://change4canton.com",
    "https://change4canton.com",
    "http://www.change4canton.com",
    "https://www.change4canton.com",
    "http://localhost:3000",
    "http://127.0.0.1:5500",
    "http://change4canton.com:3001", // por si acaso
  ];

  app.use(
    cors({
      origin: function (origin, callback) {
        // Permitir solicitudes sin origen (como aplicaciones móviles o Postman)
        if (!origin) return callback(null, true);

        if (allowedOrigins.indexOf(origin) !== -1) {
          callback(null, true);
        } else {
          console.log("Bloqueado por CORS:", origin);
          callback(new Error("No permitido por CORS"));
        }
      },
      credentials: true,
    })
  );
} else {
  // Configuración para DESARROLLO - permitir todos los orígenes
  app.use(cors());
}

app.use(bodyParser.json({ limit: "10mb" }));
app.use(express.json());

// Configuración del pool de conexiones (MODIFICADO)
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "inmobiliaria",
  port: process.env.DB_PORT || 3306,
  charset: "utf8mb4",
  connectionLimit: 10, // Límite de conexiones en el pool
  acquireTimeout: 60000, // Tiempo máximo para obtener una conexión
  timeout: 60000, // Tiempo máximo de inactividad
  waitForConnections: true, // Esperar si no hay conexiones disponibles
  queueLimit: 0, // Límite ilimitado de solicitudes en cola
};

const pool = mysql.createPool(dbConfig);

// Verificar la conexión a la base de datos (MODIFICADO)
pool.getConnection((err, connection) => {
  if (err) {
    console.error("❌ Error al conectar con la base de datos:", err);
    return;
  }
  console.log("✅ Conexión a la base de datos establecida");
  connection.release(); // Liberar la conexión de vuelta al pool
});

// Middleware para log de requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Endpoint para verificar el estado del servidor
app.get("/health", (req, res) => {
  // Verificar estado de la base de datos también (MODIFICADO)
  pool.getConnection((err, connection) => {
    if (err) {
      return res.status(500).json({
        status: "ERROR",
        message: "Error de conexión a la base de datos",
        timestamp: new Date().toISOString(),
      });
    }

    connection.ping((pingErr) => {
      connection.release();

      if (pingErr) {
        return res.status(500).json({
          status: "ERROR",
          message: "Base de datos no responde",
          timestamp: new Date().toISOString(),
        });
      }

      res.status(200).json({
        status: "OK",
        message: "Servidor y base de datos funcionando correctamente",
        timestamp: new Date().toISOString(),
      });
    });
  });
});

// [TODOS TUS ENDPOINTS EXISTENTES AQUÍ - MODIFICADOS PARA USAR POOL]
// Endpoint para registrar un usuario (MODIFICADO)
app.post("/register", (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  // Encriptar la contraseña
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error("Error al encriptar la contraseña:", err);
      return res
        .status(500)
        .json({ error: "Hubo un error al encriptar la contraseña" });
    }

    // Insertar usuario en la base de datos
    const sql =
      "INSERT INTO usuarios (username, password, email) VALUES (?, ?, ?)";

    pool.query(sql, [username, hashedPassword, email], (error, results) => {
      if (error) {
        console.error("Error al registrar el usuario:", error);
        return res
          .status(500)
          .json({ error: "Hubo un error al registrar el usuario" });
      }

      res
        .status(200)
        .json({ success: true, message: "Usuario registrado con éxito" });
    });
  });
});

// Endpoint para iniciar sesión (MODIFICADO)
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  console.log("Intento de login:", username, password);

  if (!username || !password) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  const query = "SELECT * FROM usuarios WHERE username = ?";
  pool.query(query, [username], (error, results) => {
    if (error) {
      console.error("Error en la consulta SQL:", error);
      return res
        .status(500)
        .json({ success: false, message: "Error en el servidor" });
    }

    if (results.length === 0) {
      return res
        .status(401)
        .json({ success: false, message: "Usuario no encontrado" });
    }

    const user = results[0];

    // Comparar contraseñas encriptadas
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Error al comparar la contraseña:", err);
        return res
          .status(500)
          .json({ error: "Hubo un error al verificar la contraseña" });
      }

      if (!isMatch) {
        return res
          .status(401)
          .json({ success: false, message: "Contraseña incorrecta" });
      }

      res
        .status(200)
        .json({ success: true, message: "Inicio de sesión exitoso" });
    });
  });
});

// Endpoint para obtener la historia de la empresa (MODIFICADO)
app.get("/empresahistoria", (req, res) => {
  pool.query("SELECT * FROM empresahistoria", (error, resultado) => {
    if (error) {
      console.error("Error al obtener datos:", error);
      res
        .status(500)
        .json({ error: "Error al obtener la historia de la empresa" });
    } else {
      res.json(resultado);
    }
  });
});

// Endpoint para obtener web de Oficinas de la empresa (MODIFICADO)
app.get("/empresaoficinas", (req, res) => {
  pool.query("SELECT * FROM empresaoficinas", (error, resultado) => {
    if (error) {
      console.error("Error al obtener datos:", error);
      res.status(500).json({
        error: "Error al obtener la web de las oficinas de la empresa",
      });
    } else {
      res.json(resultado);
    }
  });
});

// Endpoint para obtener información de contacto (MODIFICADO)
app.get("/contactar", (req, res) => {
  pool.query("SELECT * FROM contactar", (error, resultado) => {
    if (error) {
      console.error("Error al obtener datos de contacto:", error);
      res
        .status(500)
        .json({ error: "Error al obtener información de contacto" });
    } else {
      res.status(200).json(resultado);
    }
  });
});

// Endpoint para obtener viviendas en Alquiler (MODIFICADO)
app.get("/alquilar/:donde/:tipo", (req, res) => {
  const sql = "SELECT * FROM alquilar WHERE location = ? AND tipo = ?";
  pool.query(sql, [req.params.donde, req.params.tipo], (error, resultado) => {
    if (error) {
      console.error("Error en la consulta:", error);
      res.status(500).json({ error: "Error al realizar la consulta" });
    } else {
      console.log(resultado);
      res.status(200).json({ cantidad: resultado.length, msg: resultado });
    }
  });
});

// Endpoint para obtener viviendas según ubicación y tipo (MODIFICADO)
app.get("/comprar_vivienda/:donde/:tipo", (req, res) => {
  const sql = "SELECT * FROM comprar_vivienda WHERE location = ? AND tipo = ?";
  pool.query(sql, [req.params.donde, req.params.tipo], (error, resultado) => {
    if (error) {
      console.error("Error en la consulta:", error);
      res.status(500).json({ error: "Error al realizar la consulta" });
    } else {
      console.log(resultado);
      res.status(200).json({ cantidad: resultado.length, msg: resultado });
    }
  });
});

// Endpoint para agregar una nueva vivienda (vender) (MODIFICADO)
app.post("/vender_vivienda", (req, res) => {
  console.log("Datos recibidos:", req.body);
  const {
    titulo,
    parrafo,
    habitaciones,
    piscina,
    location,
    alquilar,
    ruta,
    alt,
    superficie,
    venta,
    tipo,
    descripcion,
  } = req.body;

  // Validar que todos los campos obligatorios estén presentes
  if (
    !titulo ||
    !parrafo ||
    habitaciones === null ||
    habitaciones === undefined ||
    piscina === null ||
    piscina === undefined ||
    !location ||
    alquilar === null ||
    alquilar === undefined ||
    !ruta ||
    !alt ||
    !superficie ||
    venta === null ||
    venta === undefined ||
    !tipo ||
    !descripcion
  ) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  // Insertar la nueva vivienda en la base de datos
  const sql = `
  INSERT INTO comprar_vivienda 
  (titulo, parrafo, habitaciones, piscina, location, alquilar, ruta, alt, superficie, venta, tipo, descripcion)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

  const values = [
    titulo,
    parrafo,
    habitaciones,
    piscina,
    location,
    alquilar,
    ruta,
    alt,
    superficie,
    venta,
    tipo,
    descripcion,
  ];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error("Error al insertar la vivienda:", error);
      return res
        .status(500)
        .json({ error: "Hubo un error al agregar la vivienda" });
    }

    res.status(200).json({
      success: true,
      message: "Vivienda agregada correctamente",
      id: results.insertId,
    });
  });
});

// Nuevo endpoint GET para obtener viviendas (MODIFICADO)
app.get("/vender_vivienda", (req, res) => {
  const publicado = req.query.publicado || 1;

  const sql = "SELECT * FROM comprar_vivienda WHERE publicado = ?";

  pool.query(sql, [publicado], (error, results) => {
    if (error) {
      console.error("Error al obtener viviendas:", error);
      return res.status(500).json({ error: "Error al obtener viviendas" });
    }
    res.status(200).json(results);
  });
});

// Ruta dinámica para políticas
app.get("/politicas/:tipo", (req, res) => {
  const { tipo } = req.params;

  pool.query(
    "SELECT * FROM politicas WHERE tipo = ? LIMIT 1",
    [tipo],
    (error, resultado) => {
      if (error) {
        console.error("Error al obtener política:", error);
        res.status(500).json({ error: "Error al obtener la política" });
      } else if (resultado.length === 0) {
        res
          .status(404)
          .json({ error: "No se encontró información para esta política" });
      } else {
        res.json(resultado[0]);
      }
    }
  );
});

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: "Algo salió mal en el servidor",
    message: "Error interno del servidor",
  });
});

// Manejo de rutas no encontradas
app.use("*", (req, res) => {
  res.status(404).json({ error: "Ruta no encontrada" });
});

// Cerrar el pool de conexiones al apagar la aplicación
process.on("SIGINT", () => {
  pool.end((err) => {
    if (err) {
      console.error("Error al cerrar el pool de conexiones:", err);
    } else {
      console.log("Pool de conexiones cerrado correctamente");
    }
    process.exit(0);
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`🚀 API arrancada en puerto ${port}`);
  console.log(`🌍 Entorno: ${process.env.NODE_ENV || "development"}`);
});

/*
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();
const port = process.env.PORT || 3001;

// Configuración de CORS para producción y desarrollo
if (process.env.NODE_ENV === "production") {
  // Configuración para PRODUCCIÓN
  const allowedOrigins = [
    "https://change4canton.com", // REEMPLAZA con tu dominio real
    "https://www.change4canton.com", // REEMPLAZA con tu dominio real
  ];

  app.use(
    cors({
      origin: function (origin, callback) {
        // Permitir solicitudes sin origen (como aplicaciones móviles o Postman)
        if (!origin) return callback(null, true);

        if (allowedOrigins.indexOf(origin) !== -1) {
          callback(null, true);
        } else {
          console.log("Bloqueado por CORS:", origin);
          callback(new Error("No permitido por CORS"));
        }
      },
      credentials: true,
    })
  );
} else {
  // Configuración para DESARROLLO - permitir todos los orígenes
  app.use(cors());
}

app.use(bodyParser.json({ limit: "10mb" }));
app.use(express.json());

// Configuración del pool de conexiones (MODIFICADO)
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "inmobiliaria",
  port: process.env.DB_PORT || 3306,
  charset: "utf8mb4",
  connectionLimit: 10, // Límite de conexiones en el pool
  acquireTimeout: 60000, // Tiempo máximo para obtener una conexión
  timeout: 60000, // Tiempo máximo de inactividad
  waitForConnections: true, // Esperar si no hay conexiones disponibles
  queueLimit: 0, // Límite ilimitado de solicitudes en cola
};

const pool = mysql.createPool(dbConfig);

// Verificar la conexión a la base de datos (MODIFICADO)
pool.getConnection((err, connection) => {
  if (err) {
    console.error("❌ Error al conectar con la base de datos:", err);
    return;
  }
  console.log("✅ Conexión a la base de datos establecida");
  connection.release(); // Liberar la conexión de vuelta al pool
});

// Middleware para log de requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Endpoint para verificar el estado del servidor
app.get("/health", (req, res) => {
  // Verificar estado de la base de datos también (MODIFICADO)
  pool.getConnection((err, connection) => {
    if (err) {
      return res.status(500).json({
        status: "ERROR",
        message: "Error de conexión a la base de datos",
        timestamp: new Date().toISOString(),
      });
    }

    connection.ping((pingErr) => {
      connection.release();

      if (pingErr) {
        return res.status(500).json({
          status: "ERROR",
          message: "Base de datos no responde",
          timestamp: new Date().toISOString(),
        });
      }

      res.status(200).json({
        status: "OK",
        message: "Servidor y base de datos funcionando correctamente",
        timestamp: new Date().toISOString(),
      });
    });
  });
});

// [TODOS TUS ENDPOINTS EXISTENTES AQUÍ - MODIFICADOS PARA USAR POOL]
// Endpoint para registrar un usuario (MODIFICADO)
app.post("/register", (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  // Encriptar la contraseña
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error("Error al encriptar la contraseña:", err);
      return res
        .status(500)
        .json({ error: "Hubo un error al encriptar la contraseña" });
    }

    // Insertar usuario en la base de datos
    const sql =
      "INSERT INTO usuarios (username, password, email) VALUES (?, ?, ?)";

    pool.query(sql, [username, hashedPassword, email], (error, results) => {
      if (error) {
        console.error("Error al registrar el usuario:", error);
        return res
          .status(500)
          .json({ error: "Hubo un error al registrar el usuario" });
      }

      res
        .status(200)
        .json({ success: true, message: "Usuario registrado con éxito" });
    });
  });
});

// Endpoint para iniciar sesión (MODIFICADO)
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  console.log("Intento de login:", username, password);

  if (!username || !password) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  const query = "SELECT * FROM usuarios WHERE username = ?";
  pool.query(query, [username], (error, results) => {
    if (error) {
      console.error("Error en la consulta SQL:", error);
      return res
        .status(500)
        .json({ success: false, message: "Error en el servidor" });
    }

    if (results.length === 0) {
      return res
        .status(401)
        .json({ success: false, message: "Usuario no encontrado" });
    }

    const user = results[0];

    // Comparar contraseñas encriptadas
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Error al comparar la contraseña:", err);
        return res
          .status(500)
          .json({ error: "Hubo un error al verificar la contraseña" });
      }

      if (!isMatch) {
        return res
          .status(401)
          .json({ success: false, message: "Contraseña incorrecta" });
      }

      res
        .status(200)
        .json({ success: true, message: "Inicio de sesión exitoso" });
    });
  });
});

// Endpoint para obtener la historia de la empresa (MODIFICADO)
app.get("/empresahistoria", (req, res) => {
  pool.query("SELECT * FROM empresahistoria", (error, resultado) => {
    if (error) {
      console.error("Error al obtener datos:", error);
      res
        .status(500)
        .json({ error: "Error al obtener la historia de la empresa" });
    } else {
      res.json(resultado);
    }
  });
});

// Endpoint para obtener web de Oficinas de la empresa (MODIFICADO)
app.get("/empresaoficinas", (req, res) => {
  pool.query("SELECT * FROM empresaoficinas", (error, resultado) => {
    if (error) {
      console.error("Error al obtener datos:", error);
      res.status(500).json({
        error: "Error al obtener la web de las oficinas de la empresa",
      });
    } else {
      res.json(resultado);
    }
  });
});

// Endpoint para obtener información de contacto (MODIFICADO)
app.get("/contactar", (req, res) => {
  pool.query("SELECT * FROM contactar", (error, resultado) => {
    if (error) {
      console.error("Error al obtener datos de contacto:", error);
      res
        .status(500)
        .json({ error: "Error al obtener información de contacto" });
    } else {
      res.status(200).json(resultado);
    }
  });
});

// Endpoint para obtener viviendas en Alquiler (MODIFICADO)
app.get("/alquilar/:donde/:tipo", (req, res) => {
  const sql = "SELECT * FROM alquilar WHERE location = ? AND tipo = ?";
  pool.query(sql, [req.params.donde, req.params.tipo], (error, resultado) => {
    if (error) {
      console.error("Error en la consulta:", error);
      res.status(500).json({ error: "Error al realizar la consulta" });
    } else {
      console.log(resultado);
      res.status(200).json({ cantidad: resultado.length, msg: resultado });
    }
  });
});

// Endpoint para obtener viviendas según ubicación y tipo (MODIFICADO)
app.get("/comprar_vivienda/:donde/:tipo", (req, res) => {
  const sql = "SELECT * FROM comprar_vivienda WHERE location = ? AND tipo = ?";
  pool.query(sql, [req.params.donde, req.params.tipo], (error, resultado) => {
    if (error) {
      console.error("Error en la consulta:", error);
      res.status(500).json({ error: "Error al realizar la consulta" });
    } else {
      console.log(resultado);
      res.status(200).json({ cantidad: resultado.length, msg: resultado });
    }
  });
});

// Endpoint para agregar una nueva vivienda (vender) (MODIFICADO)
app.post("/vender_vivienda", (req, res) => {
  console.log("Datos recibidos:", req.body);
  const {
    titulo,
    parrafo,
    habitaciones,
    piscina,
    location,
    alquilar,
    ruta,
    alt,
    superficie,
    venta,
    tipo,
    descripcion,
  } = req.body;

  // Validar que todos los campos obligatorios estén presentes
  if (
    !titulo ||
    !parrafo ||
    habitaciones === null ||
    habitaciones === undefined ||
    piscina === null ||
    piscina === undefined ||
    !location ||
    alquilar === null ||
    alquilar === undefined ||
    !ruta ||
    !alt ||
    !superficie ||
    venta === null ||
    venta === undefined ||
    !tipo ||
    !descripcion
  ) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  // Insertar la nueva vivienda en la base de datos
  const sql = `
  INSERT INTO comprar_vivienda 
  (titulo, parrafo, habitaciones, piscina, location, alquilar, ruta, alt, superficie, venta, tipo, descripcion)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

  const values = [
    titulo,
    parrafo,
    habitaciones,
    piscina,
    location,
    alquilar,
    ruta,
    alt,
    superficie,
    venta,
    tipo,
    descripcion,
  ];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error("Error al insertar la vivienda:", error);
      return res
        .status(500)
        .json({ error: "Hubo un error al agregar la vivienda" });
    }

    res.status(200).json({
      success: true,
      message: "Vivienda agregada correctamente",
      id: results.insertId,
    });
  });
});

// Nuevo endpoint GET para obtener viviendas (MODIFICADO)
app.get("/vender_vivienda", (req, res) => {
  const publicado = req.query.publicado || 1;

  const sql = "SELECT * FROM comprar_vivienda WHERE publicado = ?";

  pool.query(sql, [publicado], (error, results) => {
    if (error) {
      console.error("Error al obtener viviendas:", error);
      return res.status(500).json({ error: "Error al obtener viviendas" });
    }
    res.status(200).json(results);
  });
});

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: "Algo salió mal en el servidor",
    message: "Error interno del servidor",
  });
});

// Manejo de rutas no encontradas
app.use("*", (req, res) => {
  res.status(404).json({ error: "Ruta no encontrada" });
});

// Cerrar el pool de conexiones al apagar la aplicación
process.on("SIGINT", () => {
  pool.end((err) => {
    if (err) {
      console.error("Error al cerrar el pool de conexiones:", err);
    } else {
      console.log("Pool de conexiones cerrado correctamente");
    }
    process.exit(0);
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`🚀 API arrancada en puerto ${port}`);
  console.log(`🌍 Entorno: ${process.env.NODE_ENV || "development"}`);
});
*/

//HOLA
const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs");
const connection = require('./db');
const multer = require('multer');
const path = require('path');
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require('fs');
const jwt = require('jsonwebtoken');
const { sendResetEmail } = require('./mailer');
const cors = require("cors");
const xlsx = require("xlsx");
const excel = multer({ dest: "excel/" });


router.post("/excel-excel", excel.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No se subió ningún archivo" });
  }

  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  if (data.length === 0) {
    return res.status(400).json({ message: "El archivo Excel no tiene datos válidos" });
  }

  const values = data.map(({ id, nombre, correo, password, rol, fecha_nacimiento, sexo }) => [
    id, nombre, correo, password, rol, fecha_nacimiento, sexo
  ]);

  const query = "INSERT INTO usuarios (id, nombre, correo, password, rol, fecha_nacimiento, sexo) VALUES ?";

  connection.query(query, [values], (err, result) => {
    fs.unlinkSync(filePath);

    if (err) {
      return res.status(500).json({ message: "Error al insertar datos en la base de datos" });
    }

    res.json({ message: "✅ Datos importados con éxito", filasInsertadas: result.affectedRows });
  });
});

router.post("/excel-valvulas", excel.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No se subió ningún archivo" });
  }

  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  if (data.length === 0) {
    return res.status(400).json({ message: "El archivo Excel no tiene datos válidos" });
  }

  const values = data.map(({ id, nombre, ubicacion, estado, fecha_instalacion }) => [
    id, nombre, ubicacion, estado, fecha_instalacion
  ]);

  const query = "INSERT INTO valvulas (id, nombre, ubicacion, estado, fecha_instalacion) VALUES ?";

  connection.query(query, [values], (err, result) => {
    fs.unlinkSync(filePath);

    if (err) {
      return res.status(500).json({ message: "Error al insertar datos en la base de datos" });
    }

    res.json({ message: "✅ Datos importados con éxito", filasInsertadas: result.affectedRows });
  });
});


router.post("/excel-sensores", excel.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No se subió ningún archivo" });
  }

  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  if (data.length === 0) {
    return res.status(400).json({ message: "El archivo Excel no tiene datos válidos" });
  }

  const values = data.map(({ id, nombre, tipo, ubicacion, fecha_instalacion }) => [
    id, nombre, tipo, ubicacion, fecha_instalacion
  ]);

  const query = "INSERT INTO sensores (id, nombre, tipo, ubicacion, fecha_instalacion) VALUES ?";

  connection.query(query, [values], (err, result) => {
    fs.unlinkSync(filePath);

    if (err) {
      return res.status(500).json({ message: "Error al insertar datos en la base de datos" });
    }

    res.json({ message: "✅ Datos importados con éxito", filasInsertadas: result.affectedRows });
  });
});


router.post("/excel-riego", excel.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No se subió ningún archivo" });
  }

  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  if (data.length === 0) {
    return res.status(400).json({ message: "El archivo Excel no tiene datos válidos" });
  }

  const values = data.map(({ id, valvula_id, cantidad_agua, duracion, fecha_riego }) => [
    id, valvula_id, cantidad_agua, duracion, fecha_riego
  ]);

  const query = "INSERT INTO riegos (id, valvula_id, cantidad_agua, duracion, fecha_riego) VALUES ?";

  connection.query(query, [values], (err, result) => {
    fs.unlinkSync(filePath);

    if (err) {
      return res.status(500).json({ message: "Error al insertar datos en la base de datos" });
    }

    res.json({ message: "✅ Datos importados con éxito", filasInsertadas: result.affectedRows });
  });
});

router.post('/send-reset-code', (req, res) => {
  const { correo } = req.body;

  if (!correo) {
    return res.status(400).json({ message: 'Correo no proporcionado' });
  }

  const resetCode = Math.floor(100000 + Math.random() * 900000);
  const expirationTime = new Date(Date.now() + 15 * 60000);


  connection.query(
    'UPDATE usuarios SET resetCode = ?, resetCodeExpiration = ? WHERE correo = ?',
    [resetCode, expirationTime, correo],
    (err, results) => {
      if (err) {
        console.error('Error al insertar el código:', err);
        return res.status(500).json({ message: 'Error al enviar el código de recuperación', error: err });
      }

      if (results.affectedRows > 0) {

        sendResetEmail(correo, resetCode);

        return res.status(200).json({ message: 'Código de recuperación enviado correctamente' });
      } else {
        return res.status(404).json({ message: 'Correo no encontrado en la base de datos' });
      }
    }
  );
});

router.post('/verify-reset-code', (req, res) => {
  const { correo, codigo } = req.body;

  console.log("Datos recibidos:", correo, codigo);

  if (!correo || !codigo) {
    return res.status(400).json({ message: "Correo y código son obligatorios." });
  }

  connection.query(
    "SELECT resetCode, resetCodeExpiration FROM usuarios WHERE correo = ?",
    [correo],
    (err, results) => {
      if (err) {
        console.error("Error al verificar el código:", err);
        return res.status(500).json({ message: "Error del servidor." });
      }

      if (results.length === 0) {
        return res.status(400).json({ message: "Correo no encontrado." });
      }

      const user = results[0];


      if (!user.resetCode || user.resetCode.toString() !== codigo.toString()) {
        return res.status(400).json({ message: "Código incorrecto." });
      }

      const now = new Date();
      if (new Date(user.resetCodeExpiration) < now) {
        return res.status(400).json({ message: "Código expirado." });
      }

      return res.status(200).json({ success: true, message: "Código correcto." });
    }
  );
});


router.post("/reset-password", async (req, res) => {
  const { correo, codigo, nuevaPassword } = req.body;

  try {

    const [rows] = await connection.promise().query('SELECT * FROM usuarios WHERE correo = ?', [correo]);

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "Usuario no encontrado." });
    }

    const usuario = rows[0];


    if (!usuario.resetCode || usuario.resetCode !== codigo || Date.now() > usuario.resetCodeExpiration) {
      return res.status(400).json({ success: false, message: "Código inválido o expirado." });
    }


    const hashedPassword = await bcrypt.hash(nuevaPassword, 10);


    await connection.promise().query('UPDATE usuarios SET password = ?, resetCode = NULL, resetCodeExpiration = NULL WHERE correo = ?', [hashedPassword, correo]);

    res.json({ success: true, message: "Contraseña restablecida con éxito." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Error en el servidor." });
  }
});

const SECRET_KEY = "tu_secreto_super_seguro";
router.post("/update-password", async (req, res) => {
  const { correo, nuevaPassword } = req.body;

  if (!correo || !nuevaPassword) {
    return res.status(400).json({ error: "Datos incompletos." });
  }

  try {

    connection.query(
      "SELECT id FROM usuarios WHERE correo = ?",
      [correo],
      async (err, results) => {
        if (err) {
          console.error("Error en la consulta de usuario:", err);
          return res.status(500).json({ error: "Error en el servidor." });
        }

        if (results.length === 0) {
          return res.status(400).json({ error: "El correo no está registrado." });
        }

        const userId = results[0].id;
        const hashedPassword = await bcrypt.hash(nuevaPassword, 10);


        connection.query(
          "UPDATE usuarios SET password = ? WHERE id = ?",
          [hashedPassword, userId],
          (err) => {
            if (err) {
              console.error("Error al actualizar la contraseña:", err);
              return res.status(500).json({ error: "Error al actualizar la contraseña." });
            }
            res.json({ success: true, message: "Contraseña actualizada con éxito." });
          }
        );
      }
    );
  } catch (error) {
    console.error("Error en el servidor:", error);
    return res.status(500).json({ error: "Error en el servidor." });
  }
});

router.post("/login", (req, res) => {
  const { correo, password } = req.body;

  if (!correo || !password) {
    return res.status(400).json({ error: "Todos los campos son obligatorios." });
  }

  connection.query(
    "SELECT * FROM usuarios WHERE correo = ?",
    [correo],
    async (err, results) => {
      if (err) {
        console.error("Error al consultar usuario:", err);
        return res.status(500).json({ error: "Error interno del servidor." });
      }

      if (results.length === 0) {
        return res.status(401).json({ error: "Correo o contraseña incorrectos." });
      }

      const usuario = results[0];


      const match = await bcrypt.compare(password, usuario.password);
      if (!match) {
        return res.status(401).json({ error: "Correo o contraseña incorrectos." });
      }


      const token = jwt.sign(
        { id: usuario.id, correo: usuario.correo, rol: usuario.rol },
        SECRET_KEY,
        { expiresIn: "2h" }
      );


      const fotoNombre = usuario.foto ? path.basename(usuario.foto) : null;

      res.json({
        success: true,
        message: "Inicio de sesión exitoso.",
        usuario: {
          id: usuario.id,
          nombre: usuario.nombre,
          correo: usuario.correo,
          rol: usuario.rol,
          sexo: usuario.sexo,
          fecha_nacimiento: usuario.fecha_nacimiento,
          foto: fotoNombre,
        },
        token,
      });
    }
  );
});


router.get('/api/perfil', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acceso denegado' });
  jwt.verify(token, 'secreto', (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    connection.query('SELECT nombre, correo, rol, sexo, fecha_nacimiento, foto FROM usuarios WHERE id = ?', [decoded.id], (err, results) => {
      if (err || results.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
      res.json(results[0]);
    });
  });
});


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });


router.post("/usuarios", upload.single('foto'), (req, res) => {
  console.log("📥 Datos recibidos:", req.body);
  console.log("📸 Archivo recibido:", req.file);

  const { nombre, correo, password, rol, fecha_nacimiento, sexo } = req.body;
  const foto = req.file ? req.file.path : null;

  if (!nombre || !correo || !password || !fecha_nacimiento || !sexo || !foto) {
    console.log("❌ Error: Faltan campos obligatorios");
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }


  const calcularEdad = (fechaNacimiento) => {
    const hoy = new Date();
    const nacimiento = new Date(fechaNacimiento);
    let edad = hoy.getFullYear() - nacimiento.getFullYear();
    const mes = hoy.getMonth() - nacimiento.getMonth();
    if (mes < 0 || (mes === 0 && hoy.getDate() < nacimiento.getDate())) {
      edad--;
    }
    return edad;
  };


  if (calcularEdad(fecha_nacimiento) < 18) {
    console.log("⛔ Error: Usuario menor de edad");
    return res.status(403).json({ error: "Debes tener al menos 18 años para registrarte" });
  }


  const checkEmailQuery = "SELECT * FROM usuarios WHERE correo = ?";
  connection.query(checkEmailQuery, [correo], (err, results) => {
    if (err) {
      console.error("❌ Error al verificar correo:", err);
      return res.status(500).json({ error: "Error en el servidor" });
    }

    console.log("🔎 Resultados de búsqueda de correo:", results);

    if (results.length > 0) {
      console.log("⚠️ El correo ya está registrado:", correo);
      return res.status(400).json({ error: "El correo ya está registrado" });
    }


    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error("❌ Error al encriptar la contraseña:", err);
        return res.status(500).json({ error: "Error al encriptar la contraseña" });
      }


      const insertQuery = "INSERT INTO usuarios (nombre, correo, password, rol, foto, fecha_nacimiento, sexo) VALUES (?, ?, ?, ?, ?, ?, ?)";
      connection.query(insertQuery, [nombre, correo, hashedPassword, rol, foto, fecha_nacimiento, sexo], (err, result) => {
        if (err) {
          console.error("❌ Error al registrar usuario:", err);
          return res.status(500).json({ error: "Error al registrar usuario" });
        }
        console.log("✅ Usuario registrado con éxito:", result.insertId);
        res.status(201).json({ message: "✅ Usuario registrado con éxito", fotoUrl: foto });
      });
    });
  });
});

router.get('/usuarios', (req, res) => {
  connection.query('SELECT * FROM usuarios ORDER BY id DESC', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

router.get('/usuarios/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM usuarios WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

// Crear un nuevo registro
router.post('/usuarios', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO usuarios SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    connection.query('SELECT * FROM usuarios ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});

// Actualizar un registro
const calcularEdad = (fechaNacimiento) => {
  const hoy = new Date();
  const nacimiento = new Date(fechaNacimiento);
  let edad = hoy.getFullYear() - nacimiento.getFullYear();
  const mes = hoy.getMonth() - nacimiento.getMonth();
  if (mes < 0 || (mes === 0 && hoy.getDate() < nacimiento.getDate())) {
    edad--;
  }
  return edad;
};

// Ruta para editar usuario
// Ruta para editar usuario
router.put("/usuarios/:id", upload.single('foto'), (req, res) => {
  const id = req.params.id;
  const { nombre, correo, password, rol, fecha_nacimiento, sexo } = req.body;

  // Verificar si se ha subido una nueva foto
  let nuevaFoto = null;
  if (req.file) {
    nuevaFoto = req.file.filename; // Nombre del archivo de la foto subida
  }

  // Validar campos obligatorios
  if (!nombre || !correo || !fecha_nacimiento || !sexo || !rol) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  // Verificar que la fecha de nacimiento sea válida
  if (isNaN(new Date(fecha_nacimiento).getTime())) {
    return res.status(400).json({ error: "Fecha de nacimiento inválida" });
  }

  // Verificar edad mínima
  if (calcularEdad(fecha_nacimiento) < 18) {
    return res.status(403).json({ error: "Debes tener al menos 18 años para registrarte" });
  }

  // Verificar si el correo ya está registrado por otro usuario
  const checkEmailQuery = "SELECT id FROM usuarios WHERE correo = ? AND id != ?";
  connection.query(checkEmailQuery, [correo, id], (err, results) => {
    if (err) {
      console.error("❌ Error al verificar correo:", err);
      return res.status(500).json({ error: "Error en el servidor" });
    }

    if (results.length > 0) {
      return res.status(400).json({ error: "El correo ya está registrado por otro usuario" });
    }

    // Obtener los datos actuales del usuario (sin considerar la foto)
    const getUserQuery = "SELECT foto FROM usuarios WHERE id = ?";
    connection.query(getUserQuery, [id], (err, userResults) => {
      if (err) {
        console.error("❌ Error al obtener usuario:", err);
        return res.status(500).json({ error: "Error al obtener usuario" });
      }

      if (userResults.length === 0) {
        return res.status(404).json({ error: "Usuario no encontrado" });
      }

      // Si no se cambia la foto, usamos la foto actual
      const fotoActual = nuevaFoto || userResults[0].foto; // Si hay una nueva foto, usarla; de lo contrario, usar la actual

      // Si el usuario cambió la contraseña, encriptarla
      if (password) {
        bcrypt.hash(password, 10, (err, hashedPassword) => {
          if (err) {
            console.error("❌ Error al encriptar la contraseña:", err);
            return res.status(500).json({ error: "Error al encriptar la contraseña" });
          }

          // Actualizar usuario con nueva contraseña y los demás datos, incluida la foto
          const updateQuery = `
            UPDATE usuarios
            SET nombre = ?, correo = ?, password = ?, rol = ?, foto = ?, fecha_nacimiento = ?, sexo = ?
            WHERE id = ?
          `;
          connection.query(updateQuery, [
            nombre, correo, hashedPassword, rol, fotoActual, fecha_nacimiento, sexo, id
          ], (err) => {
            if (err) {
              console.error("❌ Error al actualizar usuario:", err);
              return res.status(500).json({ error: "Error al actualizar usuario" });
            }
            res.json({ message: "✅ Usuario actualizado con éxito" });
          });
        });
      } else {
        // Si no cambia la contraseña, actualizar sin encriptar y con foto si es necesario
        const updateQuery = `
          UPDATE usuarios
          SET nombre = ?, correo = ?, rol = ?, foto = ?, fecha_nacimiento = ?, sexo = ?
          WHERE id = ?
        `;
        connection.query(updateQuery, [
          nombre, correo, rol, fotoActual, fecha_nacimiento, sexo, id
        ], (err) => {
          if (err) {
            console.error("❌ Error al actualizar usuario:", err);
            return res.status(500).json({ error: "Error al actualizar usuario" });
          }
          res.json({ message: "✅ Usuario actualizado con éxito" });
        });
      }
    });
  });
});


// Eliminar un registro
router.delete('/usuarios/:id', (req, res) => {
  const id = req.params.id;
  connection.query('DELETE FROM usuarios WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      res.status(500).json({ error: 'Error al eliminar el registro' });
      return;
    }
    connection.query('SELECT * FROM usuarios ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});



router.post("/login/validate", (req, res) => {
  const { correo } = req.body;

  if (!correo) {
    return res.status(400).json({ error: "Correo es requerido" });
  }


  const query = "SELECT * FROM usuarios WHERE correo = ?";
  connection.query(query, [correo], (err, results) => {
    if (err) {
      console.error("Error al consultar el correo:", err);
      return res.status(500).json({ error: "Error al consultar el correo" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Correo no registrado" });
    }


    res.status(200).json({ message: "Correo válido" });
  });
});



const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Acceso denegado. No se encontró el token.' });

  jwt.verify(token, 'mi_secreto', (err, user) => {
    if (err) return res.status(403).json({ error: 'Token no válido' });
    req.user = user;
    next();
  });
};


router.get('/usuarios/:id', verifyToken, (req, res) => {
  const id = req.params.id;

  if (req.user.id !== id) {
    return res.status(403).json({ error: 'No tienes permiso para acceder a este perfil' });
  }

  const query = 'SELECT id, nombre, correo, rol, sexo, fecha_nacimiento, foto FROM usuarios WHERE id = ? LIMIT 1';
  connection.query(query, [id], (err, results) => {
    if (err) {
      console.error('Error al obtener el perfil:', err);
      return res.status(500).json({ error: 'Error al obtener el perfil' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(results[0]);
  });
});



// Obtener todos los sensores
router.get('/sensores', (req, res) => {
  connection.query('SELECT * FROM sensores', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener un sensor por su ID
router.get('/sensores/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM sensores WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

router.post('/sensores', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO sensores SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    connection.query('SELECT * FROM sensores ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});

// Actualizar un registro
router.put('/sensores/:id', (req, res) => {
  const id = req.params.id;
  const datosActualizados = req.body;
  connection.query('UPDATE sensores SET ? WHERE id = ?', [datosActualizados, id], (err, results) => {
    if (err) {
      console.error('Error al actualizar el registro:', err);
      res.status(500).json({ error: 'Error al actualizar el registro' });
      return;
    }
    connection.query('SELECT * FROM sensores ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});

// Eliminar un registro
router.delete('/sensores/:id', (req, res) => {
  const id = req.params.id;
  connection.query('DELETE FROM sensores WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      res.status(500).json({ error: 'Error al eliminar el registro' });
      return;
    }
    connection.query('SELECT * FROM sensores ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});


// Obtener todos los registros de sensores
router.get('/registros_sensores', (req, res) => {
  connection.query('SELECT * FROM registros_sensores', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener un registro de sensor por su ID
router.get('/registros_sensores/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM registros_sensores WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

// Obtener todas las válvulas
router.get('/valvulas', (req, res) => {
  connection.query('SELECT * FROM valvulas', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener una válvula por su ID
router.get('/valvulas/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM valvulas WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});
router.post('/valvulas', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO valvulas SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    connection.query('SELECT * FROM valvulas ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});

// Actualizar un registro
router.put('/valvulas/:id', (req, res) => {
  const id = req.params.id;
  const datosActualizados = req.body;
  connection.query('UPDATE valvulas SET ? WHERE id = ?', [datosActualizados, id], (err, results) => {
    if (err) {
      console.error('Error al actualizar el registro:', err);
      res.status(500).json({ error: 'Error al actualizar el registro' });
      return;
    }
    connection.query('SELECT * FROM valvulas ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});

// Eliminar un registro
router.delete('/valvulas/:id', (req, res) => {
  const id = req.params.id;
  connection.query('DELETE FROM valvulas WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      res.status(500).json({ error: 'Error al eliminar el registro' });
      return;
    }
    connection.query('SELECT * FROM valvulas ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});

// Obtener todos los riegos realizados
router.get('/riegos', (req, res) => {
  connection.query('SELECT * FROM riegos', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});


// Obtener un riego realizado por su ID
router.get('/riegos/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM riegos WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

router.post('/riegos', (req, res) => {
  const nuevoRegistro = req.body;
  connection.query('INSERT INTO riegos SET ?', nuevoRegistro, (err, results) => {
    if (err) {
      console.error('Error al crear un nuevo registro:', err);
      res.status(500).json({ error: 'Error al crear un nuevo registro' });
      return;
    }
    connection.query('SELECT * FROM riegos ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});

// Actualizar un registro
router.put('/riegos/:id', (req, res) => {
  const id = req.params.id;
  const datosActualizados = req.body;
  connection.query('UPDATE riegos SET ? WHERE id = ?', [datosActualizados, id], (err, results) => {
    if (err) {
      console.error('Error al actualizar el registro:', err);
      res.status(500).json({ error: 'Error al actualizar el registro' });
      return;
    }
    connection.query('SELECT * FROM riegos ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});

// Eliminar un registro
router.delete('/riegos/:id', (req, res) => {
  const id = req.params.id;
  connection.query('DELETE FROM riegos WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al eliminar el registro:', err);
      res.status(500).json({ error: 'Error al eliminar el registro' });
      return;
    }
    connection.query('SELECT * FROM riegos ORDER BY id DESC', (err, results) => {
      if (err) {
        console.error('Error al obtener registros:', err);
        res.status(500).json({ error: 'Error al obtener registros' });
        return;
      }
      res.json(results);
    });
  });
});


// Obtener todas las configuraciones de riego
router.get('/configuraciones_riego', (req, res) => {
  connection.query('SELECT * FROM configuraciones_riego', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener una configuración de riego por su ID
router.get('/configuraciones_riego/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM configuraciones_riego WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

// Obtener todas las alertas
router.get('/alertas', (req, res) => {
  connection.query('SELECT * FROM alertas', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener una alerta por su ID
router.get('/alertas/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM alertas WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

module.exports = router;

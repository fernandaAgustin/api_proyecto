const multer = require("multer");
const xlsx = require("xlsx");
const fs = require("fs");
const db = require("./db"); // Importamos la conexión a la BD

const upload = multer({ dest: "uploads/" });

const uploadExcel = (req, res) => {
    upload.single("file")(req, res, (err) => {
        if (err) {
            return res.status(500).json({ message: "Error al subir el archivo" });
        }

        if (!req.file) {
            return res.status(400).json({ message: "No se subió ningún archivo" });
        }

        const filePath = req.file.path;
        const workbook = xlsx.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

        const values = data.map(({ id, nombre, correo, password, rol, foto, fecha_nacimiento, sexo }) => [
            id, nombre, correo, password, rol, foto, fecha_nacimiento, sexo
        ]);

        const query = "INSERT INTO usuarios (id, nombre, correo, password, rol, foto, fecha_nacimiento, sexo) VALUES ?";

        db.query(query, [values], (err) => {
            fs.unlinkSync(filePath); // Elimina el archivo temporal

            if (err) {
                console.error("❌ Error insertando datos:", err);
                return res.status(500).json({ message: "Error al insertar datos" });
            }

            res.json({ message: "✅ Datos importados con éxito" });
        });
    });
};

module.exports = { uploadExcel };

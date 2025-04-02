const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'database-1.c5ksy2okacbh.us-east-2.rds.amazonaws.com', // Reemplaza con el endpoint de tu RDS
  user: 'admin', // Reemplaza con tu usuario de MySQL
  password: '15470294Cesar!', // Reemplaza con tu contraseña de MySQL
  database: 'sistemariego', // Nombre de tu base de datos
  port: 3306, // Puerto por defecto de MySQL en AWS RDS
  ssl: {
    rejectUnauthorized: false // Cambia a false si usas un certificado autofirmado
  }
});

connection.connect((err) => {
  if (err) {
    console.error('Error de conexión a la base de datos:', err);
    return;
  }
  console.log('Conexión exitosa a la base de datos en AWS RDS');
});

module.exports = connection;

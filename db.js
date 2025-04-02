const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'database-1.c5ksy2okacbh.us-east-2.rds.amazonaws.com',
  user: 'admin',
  password: '15470294Cesar!',
  database: 'sistemariego',
  port: 3306,
  ssl: { rejectUnauthorized: false }
});

connection.connect((err) => {
  if (err) {
    console.error('❌ Error de conexión a la base de datos:', err.code, err.message);
    return;
  }
  console.log('✅ Conexión exitosa a la base de datos en AWS RDS');
});

module.exports = connection;

import mysql from 'mysql2'
import dotenv from 'dotenv'
dotenv.config()
//
const conn = mysql.createConnection({
  host: `${process.env.DB_HOST}`,
  user: `${process.env.DB_USER}`,
  password: `${process.env.DB_PASSWORD}`,
  database: `${process.env.DB_NAME}`,
  multipleStatements: true
});
conn.connect(function(err) {
  if (err) throw err;
  console.log('Database is connected successfully !');
});
export default conn;
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();

app.use(bodyParser.json());
app.use(cors());

const PORT = 8000
app.listen(PORT, () => {
  console.log(`Servidor backend escuchando en el puerto ${PORT}`);
});



const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'registro_usuarios',
  password: '123456',
  port: 5432, 
});


app.post('/reg', async (req, res) => {
  const { user, name, password, password2, email, phone } = req.body;

  const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

  if (existingUser.rows.length > 0) {
    return res.status(400).json({ message: 'El correo electrónico ya está en uso' });
    console.log("Correo ya en uso")
  }

  // Hashea la contraseña antes de almacenarla en la base de datos
  const hashedPassword = await bcrypt.hash(password, 10);

  
  try {
    const result = await pool.query('INSERT INTO users (username, name, password, email, phone) VALUES ($1, $2, $3, $4, $5) RETURNING *', [user, name, hashedPassword, email, phone]);
    res.status(201).json({ message: 'Usuario registrado exitosamente', user: result.rows[0] });
  } catch (error) {
    console.error('Error al registrar el usuario', error);
    res.status(500).json({ message: 'Error al registrar el usuario' });
  }
});


app.post('/login', async (req, res) => {
  const { user, password } = req.body;

  const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [user]);

  if (existingUser.rows.length > 0) {
    return res.status(400).json({ message: 'usario encontrado' });
    console.log("Correo ya en uso")}
    try {
      const client = await pool.connect();
      const result = await client.query('SELECT * FROM usuarios WHERE usuario = $1', [user]);
      client.release();
  
      if (result.rows.length === 1) {
        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
  
        if (passwordMatch) {
          
          res.sendStatus(200); 
        } else {
          
          res.sendStatus(401);
        }
      } else {
        // Usuario no encontrado, devuelve un estado no autorizado
        res.sendStatus(401);
      }
    } catch (error) {
      console.error('Error en el inicio de sesión:', error);
      res.sendStatus(500); // Error interno del servidor
    }
  }

  


  
);




// Configura el puerto del servidor

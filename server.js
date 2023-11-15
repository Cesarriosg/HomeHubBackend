// Importación de módulos
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

// Configuración de Express
const app = express();
app.use(bodyParser.json());
app.use(cors());

// Configuración de la base de datos
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'registro_usuarios',
  password: '123456',
  port: 5432,
});

// Configuración del servidor
const PORT = 8000
app.listen(PORT, () => {
  console.log(`Servidor backend escuchando en el puerto ${PORT}`);
});

// Manejo y funcion de la ruta "/reg" (Registro de usuario)
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

// Manejo y funcion de la ruta "/login" (Inicio de sesión)
app.post('/login', async (req, res) => {
  const { user, password } = req.body;

  const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [user]);

  if (existingUser.rows.length > 0) {
    return res.status(400).json({ message: 'usario encontrado' });
    console.log("Correo ya en uso")
  }

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
});

// Configuración del transporte de nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'correo@gmail.com',
    pass: 'contraseña'
  }
});

// Manejo y funcion de la ruta "/forgot-password" (recuperacion de contraseña)
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Verificar si el correo electrónico existe en la base de datos
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'No se encontró ninguna cuenta asociada con este correo electrónico.' });
    }

    // Generar un token de restablecimiento de contraseña válido por un tiempo limitado
    const token = jwt.sign({ userId: user.rows[0].id }, 'claveSuperSecretaXD', { expiresIn: '1h' });

    async function sendResetEmail(email, token) {
      const mailOptions = {
        from: 'correo@gmail.com',
        to: email,
        subject: 'Restablecimiento de Contraseña',
        text: `Haz clic en el siguiente enlace para restablecer tu contraseña: http://tuaplicacion.com/reset-password?token=${token}`
      };

      try {
        await transporter.sendMail(mailOptions);
        console.log(`Correo electrónico de restablecimiento enviado a ${email}`);
      } catch (error) {
        console.error('Error al enviar el correo electrónico:', error);
        // Puedes lanzar un error personalizado para manejarlo en el bloque catch de la ruta principal
        throw new Error('EMAIL_SENDING_ERROR');
      }
    }

    module.exports = { sendResetEmail };

    res.status(200).json({ message: 'Se ha enviado un enlace de restablecimiento de contraseña por correo electrónico.' });
  } catch (error) {
    console.error('Error al solicitar restablecimiento de contraseña:', error);

    // Manejar específicamente los errores relacionados con el envío de correo electrónico
    if (error.code === 'EMAIL_SENDING_ERROR') {
      return res.status(500).json({ message: 'Error al enviar el correo electrónico con el enlace de restablecimiento de contraseña.' });
    }

    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Ruta para restablecer la contraseña con el token
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    // Verificar y decodificar el token
    const decodedToken = jwt.verify(token, 'claveSuperSecretaXD');

    // Cambiar la contraseña en la base de datos
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, decodedToken.userId]);

    res.status(200).json({ message: 'Contraseña restablecida con éxito.' });
  } catch (error) {
    console.error('Error al restablecer la contraseña:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});
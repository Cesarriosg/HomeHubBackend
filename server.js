// Importación de módulos
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const { callbackPromise } = require('nodemailer/lib/shared');

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
  const { email, password } = req.body;

  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (user.rows.length === 0) {
      console.log('Usuario no encontrado:', email);
      return res.status(401).json({ message: 'Usuario no encontrado' });
    }

    const passwordMatch = await bcrypt.compare(password, user.rows[0].password);

    if (!passwordMatch) {
      console.log('Contraseña incorrecta para el usuario:', email);
      return res.status(401).json({ message: 'Contraseña incorrecta' });
    }

    const token = jwt.sign({ userId: user.rows[0].id }, 'your-secret-key', { expiresIn: '1h' });

    console.log('Inicio de sesión exitoso para el usuario:', email);
    res.json({ message: 'Inicio de sesión exitoso', token });
  } catch (error) {
    console.error('Error al iniciar sesión', error);
    res.status(500).json({ message: 'Error al iniciar sesión', error: error.message });
  }
});

// Configuración del transporte de nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'proyectohomehub@gmail.com',
    pass: 'zwxn zmja rfjz kryh'
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
        from: 'proyectohomehub@gmail.com',
        to: email,
        subject: 'Restablecimiento de Contraseña',
        text: `Haz clic en el siguiente enlace para restablecer tu contraseña` //: http://tuaplicacion.com/reset-password?token=${token}
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

//manejo de imagen
const upload = multer({
  storage: multer.memoryStorage(), // Almacena la imagen en memoria
  limits: {
    fileSize: 2 * 1024 * 1024, // Límite de tamaño en bytes (2MB)
  },
  fileFilter: (req, file, callback) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowedMimes.includes(file.mimetype)) {
      callback(null, true);
    } else {
      callback(new Error('Tipo de archivo no válido. Solo se permiten imágenes JPEG, PNG o GIF.'));
    }
  },
});

//completar perfil
app.put('/users/:username/completar', upload.single('imagenperfil'), async (req, res) => {

  console.log('PUT /username/:username');
  console.log('req.params:', req.params);
  console.log('req.body:', req.body);

  const username = req.params.username; 
  const { descripcion, experiencia, proyectosrealizados } = req.body;

  try {
    // Validaciones de los campos
    if (!descripcion || isNaN(experiencia) || isNaN(proyectosrealizados)) {
      res.status(400).json({ error: 'Los datos proporcionados son inválidos.' });
      return;
    }
    if (experiencia < 0 || experiencia > 100) {
      res.status(400).json({ error: 'El valor de años de experiencia debe estar entre 0 y 100.' });
      return;
    }
    
    if (proyectosrealizados < 0 || proyectosrealizados > 1000) {
      res.status(400).json({ error: 'El valor de proyectos realizados debe estar entre 0 y 1000.' });
      return;
    }
    // Completa el perfil del usuario  en la base de datos
    const updateQuery = "\n      UPDATE users\n      SET descripcion = $1, experiencia = $2, proyectosrealizados = $3, imagenperfil = $4 \n      WHERE username = $5 \n    ";
    
    const imagenperfil = req.file.buffer;
    
    await pool.query(updateQuery, [descripcion, experiencia, proyectosrealizados, imagenperfil, username]);

    res.status(200).json({ mensaje: 'Perfil completado con éxito' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al completar el perfil' });
  }
});

//actualizar perfil

const SECRET_KEY = 'Claveau';

// Middleware para autenticación de usuarios
const authenticateUser = (req, res, next) => {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ message: 'Token de autenticación no proporcionado' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token de autenticación inválido' });
  }
};

// Middleware para autorización de edición de perfil
const authorizeEditProfile = (req, res, next) => {
  const userId = req.user.userId;
  const id = req.params.id;

  if (userId !== id) {
    return res.status(403).json({ message: 'No tienes permiso para editar este perfil' });
  }

  next();
};

app.put('/users/:username/editar', authenticateUser, authorizeEditProfile, upload.single('imagenperfil'), async (req, res) => {
  const username = req.params.username;
  const { name, email, descripcion, experiencia, proyectosrealizados, phone } = req.body;

  const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

  if (existingUser.rows.length > 0) {
    return res.status(400).json({ message: 'El correo electrónico ya está en uso' });
    console.log("Correo ya en uso")
  }

  try {
    
    if (!name || !email || !descripcion || isNaN(experiencia) || isNaN(proyectosrealizados)) {
      res.status(400).json({ error: 'Los datos proporcionados son inválidos.' });
      return;
    }
    if (experiencia < 0 || experiencia > 100) {
      res.status(400).json({ error: 'El valor de años de experiencia debe estar entre 0 y 100.' });
      return;
    }
    
    if (proyectosrealizados < 0 || proyectosrealizados > 1000) {
      res.status(400).json({ error: 'El valor de proyectos realizados debe estar entre 0 y 1000.' });
      return;
    }
    // Manejar imagen de perfil
    const imagenperfil = req.file ? req.file.buffer : null;

    // Actualizar la información en la base de datos
    const updateQuery = `
      UPDATE users
      SET name = $1, email = $2, descripcion = $3, experiencia = $4, proyectosrealizados = $5, phone = $6, imagenperfil = $7
      WHERE username = $8
      RETURNING *;
    `;

    const result = await pool.query(updateQuery, [name, email, descripcion, experiencia, proyectosrealizados, phone, imagenperfil, username]);

    // Registrar la edición en el registro de auditoría 
    const auditLogQuery = `
      INSERT INTO audit_log (user_id, action, timestamp)
      VALUES ($1, $2, current_timestamp);
    `;

    await pool.query(auditLogQuery, [result.rows[0].id, 'edit_profile']);

    res.status(200).json({ message: 'Perfil editado con éxito', user: result.rows[0] });
  } catch (error) {
    console.error('Error al editar el perfil:', error);
    res.status(500).json({ message: 'Error al editar el perfil' });
  }
});

// Ruta para cambiar la contraseña
app.post('/change-password', async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id; // Suponiendo que tienes información del usuario en el objeto req.user después de la autenticación

  try {
    // Verificar la contraseña actual del usuario
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);

    if (user.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    const passwordMatch = await bcrypt.compare(currentPassword, user.rows[0].password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'La contraseña actual no es válida.' });
    }

    // Generar un token de restablecimiento de contraseña para la nueva contraseña
    const token = jwt.sign({ userId }, 'claveSuperSecretaXD', { expiresIn: '1h' });

    // Cambiar la contraseña en la base de datos
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);

    // Enviar el token por correo electrónico al usuario
    await sendResetEmail(user.rows[0].email, token);

    res.status(200).json({ message: 'Contraseña cambiada con éxito.' });
  } catch (error) {
    console.error('Error al cambiar la contraseña:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Ruta para obtener proyectos de un usuario específico
app.get('/users/:username/proyectos', async (req, res) => {
  const username = req.params.username;

  try {
    // Obtener el ID del usuario
    const userIdQuery = 'SELECT id FROM users WHERE username = $1';
    const userIdResult = await pool.query(userIdQuery, [username]);

    if (userIdResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

    const userId = userIdResult.rows[0].id;

    // Obtener proyectos asociados al usuario
    const proyectosQuery = 'SELECT * FROM proyectos WHERE user_id = $1';
    const proyectosResult = await pool.query(proyectosQuery, [userId]);

    res.status(200).json({ proyectos: proyectosResult.rows });
  } catch (error) {
    console.error('Error al obtener proyectos del usuario:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Ruta protegida para obtener proyectos de un usuario específico
// solo los usuarios autenticados puedan ver sus proyectos,
//se puede proteger esta ruta utilizando el middleware de autenticación que ya se ha creado (authenticateUser).
app.get('/users/:username/proyectos', authenticateUser, async (req, res) => {
  // ... (resto del código)
});

const jwt = require('jsonwebtoken');

// Esta es la misma palabra secreta que pusiste en tu index.js
const JWT_SECRET = 'Pollo';

// Este es nuestro "guardián"
const authMiddleware = (req, res, next) => {
  try {
    // 1. Buscamos el token en los "headers" de la petición.
    // El frontend lo enviará en un formato: "Bearer <token...>"
    const authHeader = req.headers.authorization;

    // 2. Verificamos si el header y el token existen
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: "Acceso denegado. No se proporcionó token." });
    }

    // 3. Extraemos el token (quitamos la palabra "Bearer ")
    const token = authHeader.split(' ')[1];

    // 4. Verificamos que el token sea válido
    // jwt.verify() hace la magia: decodifica y revisa la firma.
    // Si la firma no coincide con nuestra JWT_SECRET, fallará.
    const decodedPayload = jwt.verify(token, JWT_SECRET);

    // 5. ¡El token es válido!
    // Guardamos los datos del usuario (que estaban en el token)
    // en el objeto "req" para que nuestras rutas futuras lo puedan usar.
    req.user = decodedPayload; // ej. req.user = { userId: '12345', username: 'loboa' }

    // 6. Le decimos a Express: "Todo bien, continúa a la siguiente función"
    next();

  } catch (error) {
    // Si jwt.verify() falla (token expirado, firma inválida)
    console.error("Error en el middleware de autenticación:", error.message);
    res.status(401).json({ message: "Token inválido o expirado." });
  }
};

module.exports = authMiddleware;
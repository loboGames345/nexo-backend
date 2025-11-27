// index.js (Backend)

// 1. Importaciones
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
require('dotenv').config();

const User = require('./models/User');
const Conversation = require('./models/Conversation');
const Message = require('./models/Message');
const Block = require('./models/Block');
const authMiddleware = require('./middleware/authMiddleware');
const http = require('http');
const { Server } = require("socket.io");

// 2. Crear la aplicación y el servidor
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

// 3. Middlewares
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 4. Configuración de Claves y BD
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const DEFAULT_PROFILE_PIC = 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png';
const DEFAULT_GROUP_PIC = 'https://cdn.pixabay.com/photo/2016/11/14/17/39/group-1824145_1280.png';

cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

mongoose.connect(MONGO_URI)
  .then(() => console.log("¡Conectado a MongoDB Atlas!"))
  .catch((error) => console.error("Error al conectar a MongoDB:", error));

// 5. Mapas de Usuarios
let userSocketMap = {};
let socketUserMap = {};
let onlineUsersMap = {};
let activeChatMap = {};

const getUniqueOnlineCount = () => {
  return Object.keys(onlineUsersMap).length;
};

// 6. Lógica de Socket.IO
io.on('connection', (socket) => {
  console.log('Conexión establecida:', socket.id);
  socket.emit('updateUserCount', getUniqueOnlineCount());
  
  socket.on('registerUser', ({ userId, username }) => {
    if (userId) {
      userSocketMap[userId] = socket.id;
      socketUserMap[socket.id] = userId;
      onlineUsersMap[userId] = username;
      console.log(`Usuario ${username} (${userId}) registrado.`);
      io.emit('updateOnlineUsers', onlineUsersMap);
      io.emit('updateUserCount', getUniqueOnlineCount());
    }
  });
  
  socket.on('joinChatRoom', (chatId) => {
    activeChatMap[socket.id] = chatId;
  });
  
  socket.on('leaveChatRoom', () => {
    delete activeChatMap[socket.id];
  });
  
  socket.on('disconnect', () => {
    const userId = socketUserMap[socket.id];
    if (userId) {
      delete userSocketMap[userId];
      delete onlineUsersMap[userId];
      delete socketUserMap[socket.id];
      console.log(`Usuario ${userId} desconectado.`);
      io.emit('updateOnlineUsers', onlineUsersMap);
      io.emit('updateUserCount', getUniqueOnlineCount());
    }
    delete activeChatMap[socket.id];
  });
});

// 

// 7. RUTA DE REGISTRO (CON VALIDACIÓN DE CONTRASEÑA SEGURA)
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

    if (!passwordRegex.test(password)) {
      return res.status(400).json({ 
        message: "La contraseña es muy débil. Debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un símbolo." 
      });
    }

    const existingUser = await User.findOne({ username: { $regex: `^${username}$`, $options: 'i' } });
    if (existingUser) return res.status(400).json({ message: "El nombre de usuario ya existe." });
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const newUser = new User({ username, password: hashedPassword });
    const savedUser = await newUser.save();
    
    const expiresIn = '1h';
    const token = jwt.sign({ userId: savedUser._id, username: savedUser.username }, JWT_SECRET, { expiresIn: expiresIn });
    const profilePicForFrontend = savedUser.profilePictureUrl || DEFAULT_PROFILE_PIC;
    
    res.status(201).json({ message: "¡Usuario registrado e iniciado sesión!", token: token, userId: savedUser._id, username: savedUser.username, profilePictureUrl: profilePicForFrontend, bio: savedUser.bio });
  
  } catch (error) { 
    console.error("Error en register:", error);
    res.status(500).json({ message: "Error en el servidor." }); 
  }
});

// 8. RUTA DE LOGIN
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username: { $regex: `^${username}$`, $options: 'i' } });
    if (!user) return res.status(400).json({ message: "Usuario o contraseña incorrectos." });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Usuario o contraseña incorrectos." });
    const expiresIn = '1h';
    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: expiresIn });
    const profilePicForFrontend = user.profilePictureUrl || DEFAULT_PROFILE_PIC;
    res.status(200).json({ message: "¡Inicio de sesión exitoso!", token: token, userId: user._id, username: user.username, profilePictureUrl: profilePicForFrontend, bio: user.bio });
  } catch (error) { res.status(500).json({ message: "Error en el servidor." }); }
});

// 9. Ruta de prueba
app.get('/', (req, res) => res.json({ message: "¡Servidor de chat funcionando!" }));

// 10. Ruta protegida
app.get('/test-protected', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  const profilePicForFrontend = user.profilePictureUrl || DEFAULT_PROFILE_PIC;
  res.status(200).json({ message: `¡Hola!`, userData: { userId: user._id, username: user.username, profilePictureUrl: profilePicForFrontend, bio: user.bio } });
});

// --- 11. RUTAS DE CONVERSACIONES ---

app.post('/conversations', authMiddleware, async (req, res) => {
  try {
    const myId = req.user.userId;
    const { otherUsername } = req.body;
    const otherUser = await User.findOne({ username: { $regex: `^${otherUsername}$`, $options: 'i' } });
    
    if (!otherUser) return res.status(404).json({ message: "El usuario no existe." });
    if (otherUser._id.toString() === myId) return res.status(400).json({ message: "No puedes enviarte una solicitud a ti mismo." });
    
    const iBlockedThem = await Block.findOne({ blockerId: myId, blockedId: otherUser._id });
    if (iBlockedThem) return res.status(403).json({ message: "Has bloqueado a este usuario. Debes desbloquearlo para iniciar un chat." });
    const theyBlockedMe = await Block.findOne({ blockerId: otherUser._id, blockedId: myId });
    if (theyBlockedMe) return res.status(403).json({ message: "Este usuario te ha bloqueado." });

    let conversation = await Conversation.findOne({
      participants: { $all: [myId, otherUser._id] },
      isGroup: false
    });

    if (conversation) {
       if (conversation.deletedBy.includes(myId)) {
           conversation.deletedBy = conversation.deletedBy.filter(id => id !== myId);
           conversation.clearedHistoryAt.set(myId, Date.now());
           if (conversation.status === 'pending') conversation.status = 'active';
           await conversation.save();
       }

       const populatedConv = await Conversation.findById(conversation._id)
          .populate('participants', 'username profilePictureUrl bio')
          .populate('initiatedBy', 'username');
       
       const receiverId = otherUser._id.toString();
       const receiverSocketId = userSocketMap[receiverId];
       if (receiverSocketId) {
          io.to(receiverSocketId).emit('chatReadded', populatedConv);
       }

       return res.status(200).json(populatedConv);
    }

    const unreadMap = new Map();
    unreadMap.set(myId, 0);
    unreadMap.set(otherUser._id.toString(), 0);
    
    const newConversation = new Conversation({
      participants: [myId, otherUser._id],
      initiatedBy: myId,
      status: 'pending', 
      isGroup: false,
      groupAdmin: [myId],
      unreadCounts: unreadMap
    });
    const savedConversation = await newConversation.save();
    
    const populatedConversation = await Conversation.findById(savedConversation._id)
        .populate('participants', 'username profilePictureUrl bio')
        .populate('initiatedBy', 'username');
        
    const receiverId = otherUser._id.toString();
    const receiverSocketId = userSocketMap[receiverId];
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('newChatRequest', populatedConversation);
    }
    res.status(201).json(populatedConversation);
  } catch (error) {
    console.error("Error en POST /conversations:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

app.get('/conversations', authMiddleware, async (req, res) => {
  try {
    const myId = req.user.userId;
    
    let conversations = await Conversation.find({
      participants: { $in: [myId] },
      deletedBy: { $nin: [myId] }
    })
    .populate('participants', 'username profilePictureUrl bio')
    .populate('initiatedBy', 'username profilePictureUrl')
    .populate('groupAdmin', 'username profilePictureUrl')
    .populate('groupFounder', 'username profilePictureUrl'); 

    const blocks = await Block.find({ $or: [{ blockerId: myId }, { blockedId: myId }] });
    const blockedUserIds = new Set();
    blocks.forEach(b => {
        if (b.blockerId.toString() === myId) blockedUserIds.add(b.blockedId.toString());
        if (b.blockedId.toString() === myId) blockedUserIds.add(b.blockerId.toString());
    });

// Dentro de app.get('/conversations', ...)
    
    const conversationsWithBlockStatus = conversations.map(conv => {
        
        const convObj = conv.toObject({ flattenMaps: true }); 

        if (!convObj.isGroup) {
            const other = convObj.participants.find(p => p._id.toString() !== myId);
            if (other && blockedUserIds.has(other._id.toString())) {
                convObj.hasBlock = true;
            } else {
                convObj.hasBlock = false;
            }
        } else {
            convObj.hasBlock = false;
        }
        return convObj;
    });

    res.status(200).json(conversationsWithBlockStatus);
  } catch (error) {
    console.error("Error en GET /conversations:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

app.post('/conversations/:id/accept', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const myId = req.user.userId;
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) return res.status(404).json({ message: "Conversación no encontrada."});
    if (!conversation.participants.includes(myId) || conversation.initiatedBy.toString() === myId) return res.status(403).json({ message: "No autorizado." });
    
    const initiatorId = conversation.initiatedBy.toString();
    const iBlockedThem = await Block.findOne({ blockerId: myId, blockedId: initiatorId });
    if (iBlockedThem) return res.status(403).json({ message: "Has bloqueado a este usuario." });
    const theyBlockedMe = await Block.findOne({ blockerId: initiatorId, blockedId: myId });
    if (theyBlockedMe) return res.status(403).json({ message: "Este usuario te ha bloqueado." });

    if (conversation.status === 'active') return res.status(400).json({ message: "El chat ya está activo."});
    
    conversation.unreadCounts.set(myId, 0);
    conversation.status = 'active';
    await conversation.save();
    
    const populatedConversation = await Conversation.findById(conversation._id)
        .populate('participants', 'username profilePictureUrl bio')
        .populate('initiatedBy', 'username');
    
    const initiatorSocketId = userSocketMap[initiatorId];
    if (initiatorSocketId) {
      io.to(initiatorSocketId).emit('chatRequestAccepted', populatedConversation);
    }
    const mySocketId = userSocketMap[myId];
    if (mySocketId) {
      io.to(mySocketId).emit('chatRequestAccepted', populatedConversation);
    }

    res.status(200).json(populatedConversation);
  } catch (error) {
    console.error("Error en POST accept:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

app.post('/conversations/:id/reject', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const myId = req.user.userId;
    const conversation = await Conversation.findById(conversationId);

    if (!conversation) return res.status(404).json({ message: "Solicitud no encontrada." });
    if (conversation.status !== 'pending') return res.status(400).json({ message: "Esta solicitud ya no está pendiente." });
    
    if (conversation.initiatedBy.toString() === myId) {
        return res.status(403).json({ message: "No puedes rechazar tu propia solicitud." });
    }

    await Conversation.findByIdAndDelete(conversationId);

    res.status(200).json({ message: "Solicitud rechazada." });
  } catch (error) {
    console.error("Error en POST reject:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// --- 12. RUTAS DE MENSAJES (BLOQUE COMPLETO CORREGIDO) ---

// A. OBTENER MENSAJES (Cargar chat)
app.get('/conversations/:id/messages', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const myId = req.user.userId;
    const conversation = await Conversation.findById(conversationId);
    
    if (!conversation) return res.status(404).json({ message: "No encontrada." });
    if (conversation.status !== 'active' || !conversation.participants.includes(myId)) return res.status(403).json({ message: "No autorizado." });

    const myClearDate = conversation.clearedHistoryAt.get(myId) || new Date(0);

    const messages = await Message.find({ 
        conversationId: conversationId,
        createdAt: { $gt: myClearDate }
    })
    .populate('sender', 'username profilePictureUrl');
    
    res.status(200).json(messages);
  } catch (error) {
    console.error("Error en GET messages:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// B. ENVIAR MENSAJE DE SOLO TEXTO
app.post('/conversations/:id/messages', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const myId = req.user.userId;
    const { content } = req.body; 
    
    // 1. Validaciones
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(myId) || conversation.status !== 'active') {
       return res.status(403).json({ message: "No autorizado." });
    }

    if (!conversation.isGroup) {
      const otherUserId = conversation.participants.find(p => p.toString() !== myId);
      const iBlockedThem = await Block.findOne({ blockerId: myId, blockedId: otherUserId });
      if (iBlockedThem) return res.status(403).json({ message: "Has bloqueado a este usuario." });
      const theyBlockedMe = await Block.findOne({ blockerId: otherUserId, blockedId: myId });
      if (theyBlockedMe) return res.status(403).json({ message: "Este usuario te ha bloqueado." });
    }

    // 2. Unread counts
    conversation.deletedBy = conversation.deletedBy || [];
    conversation.participants.forEach(pId => {
      const pIdString = pId.toString();
      if (pIdString !== myId && !conversation.deletedBy.includes(pIdString)) {
          const socketId = userSocketMap[pIdString];
          const activeChatId = activeChatMap[socketId];
          if (activeChatId !== conversationId) {
              const currentCount = conversation.unreadCounts.get(pIdString) || 0;
              conversation.unreadCounts.set(pIdString, currentCount + 1);
          }
      }
    });
    
    await conversation.save();
    
    // 3. Guardar Mensaje
    const newMessage = new Message({ 
        conversationId: conversationId, 
        sender: myId, 
        content: content, 
        type: 'text' 
    });
    const savedMessage = await newMessage.save();
    
    // 4. Emitir Socket
    const populatedMessage = await Message.findById(savedMessage._id).populate('sender', 'username profilePictureUrl');
    const populatedConv = await Conversation.findById(conversation._id)
        .populate('participants', 'username profilePictureUrl bio')
        .populate('groupAdmin', 'username')
        .populate('groupFounder', 'username');

    conversation.participants.forEach(pId => {
      const pIdString = pId.toString();
      if (!conversation.deletedBy.includes(pIdString)) {
          const socketId = userSocketMap[pIdString];
          if (socketId) {
            io.to(socketId).emit('newMessage', populatedMessage);
            io.to(socketId).emit('conversationUpdated', populatedConv);
          }
      }
    });

    res.status(201).json(populatedMessage);
  } catch (error) {
    console.error("Error en POST messages (texto):", error);
    res.status(500).json({ message: "Error al enviar texto." });
  }
});

// D. BORRADO MASIVO
app.post('/messages/bulk-delete', authMiddleware, async (req, res) => {
  try {
    const { messageIds } = req.body;
    const myId = req.user.userId;
    const myUsername = req.user.username;

    if (!messageIds || messageIds.length === 0) return res.status(400).json({ message: "Sin selección." });

    const messages = await Message.find({ _id: { $in: messageIds } });
    if (messages.length === 0) return res.status(404).json({ message: "No encontrados." });

    const conversationId = messages[0].conversationId;
    const updates = [];

    for (const message of messages) {
        if (message.sender.toString() !== myId) continue;
        const mediaCount = message.mediaUrls ? message.mediaUrls.length : 0;
        const hasVideo = message.type === 'video';
        
        let placeholder = `**${myUsername}** ha borrado este mensaje`;
        if (message.type === 'mixed') placeholder = `**${myUsername}** ha borrado estos archivos`;
        else if (hasVideo) placeholder = mediaCount > 1 ? `**${myUsername}** ha borrado videos` : `**${myUsername}** ha borrado video`;
        else if (mediaCount > 0) placeholder = mediaCount > 1 ? `**${myUsername}** ha borrado imágenes` : `**${myUsername}** ha borrado imagen`;

        message.content = placeholder;
        message.mediaUrls = [];
        message.type = 'text';
        message.isDeleted = true;
        updates.push(message.save());
    }

    await Promise.all(updates);

    const conversation = await Conversation.findById(conversationId);
    if (conversation) {
        const populatedMessages = await Message.find({ _id: { $in: messageIds } }).populate('sender', 'username profilePictureUrl');
        conversation.participants.forEach(pId => {
            const socketId = userSocketMap[pId.toString()];
            if (socketId) io.to(socketId).emit('messagesBulkUpdated', populatedMessages);
        });
    }
    res.status(200).json({ message: "Eliminados." });
  } catch (error) {
    console.error("Error bulk-delete:", error);
    res.status(500).json({ message: "Error al eliminar." });
  }
});

// E. BORRADO INDIVIDUAL
app.delete('/messages/:id', authMiddleware, async (req, res) => {
  try {
    const { id: messageId } = req.params;
    const myId = req.user.userId;
    const myUsername = req.user.username;

    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ message: "No encontrado." });
    if (message.sender.toString() !== myId) return res.status(403).json({ message: "No autorizado." });

    const mediaCount = message.mediaUrls ? message.mediaUrls.length : 0;
    const placeholder = getDeletePlaceholder(myUsername, message.type, mediaCount);

    message.content = placeholder;
    message.mediaUrls = []; 
    message.type = 'text';
    message.isDeleted = true;
    
    const updatedMessage = await message.save();
    const populatedMessage = await Message.findById(updatedMessage._id).populate('sender', 'username profilePictureUrl');

    const conversation = await Conversation.findById(message.conversationId);
    if (conversation) {
        conversation.participants.forEach(pId => {
            const socketId = userSocketMap[pId.toString()];
            if (socketId) io.to(socketId).emit('messageUpdated', populatedMessage);
        });
    }
    res.status(200).json({ message: "Eliminado." });
  } catch (error) {
    console.error("Error delete:", error);
    res.status(500).json({ message: "Error al eliminar." });
  }
});

// --- RUTA INDIVIDUAL PARA "BORRAR" MENSAJE (Soft Delete) ---
app.delete('/messages/:id', authMiddleware, async (req, res) => {
  try {
    const { id: messageId } = req.params;
    const myId = req.user.userId;
    const myUsername = req.user.username;

    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ message: "Mensaje no encontrado." });

    if (message.sender.toString() !== myId) {
        return res.status(403).json({ message: "No puedes borrar mensajes de otros." });
    }

    const mediaCount = message.mediaUrls ? message.mediaUrls.length : 0;
    const placeholder = getDeletePlaceholder(myUsername, message.type, mediaCount);

    message.content = placeholder;
    message.mediaUrls = []; 
    message.type = 'text';
    message.isDeleted = true; // --- NUEVO: Bandera de borrado
    
    const updatedMessage = await message.save();
    const populatedMessage = await Message.findById(updatedMessage._id).populate('sender', 'username profilePictureUrl');

    const conversation = await Conversation.findById(message.conversationId);
    if (conversation) {
        conversation.participants.forEach(pId => {
            const socketId = userSocketMap[pId.toString()];
            if (socketId) {
                io.to(socketId).emit('messageUpdated', populatedMessage);
            }
        });
    }

    res.status(200).json({ message: "Mensaje eliminado." });

  } catch (error) {
    console.error("Error en DELETE /messages/:id", error);
    res.status(500).json({ message: "Error al eliminar mensaje." });
  }
});

// - Reemplaza toda la ruta "C. ENVIAR ARCHIVOS" con esto:

// C. ENVIAR ARCHIVOS (SEPARADOS: UNO POR MENSAJE)
app.post('/conversations/:id/messages/media', authMiddleware, upload.array('files', 5), async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const myId = req.user.userId;
    const { content } = req.body; 
    
    // 1. Validaciones iniciales
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(myId) || conversation.status !== 'active') {
       return res.status(403).json({ message: "No autorizado." });
    }

    if (!conversation.isGroup) {
      const otherUserId = conversation.participants.find(p => p.toString() !== myId);
      const iBlockedThem = await Block.findOne({ blockerId: myId, blockedId: otherUserId });
      if (iBlockedThem) return res.status(403).json({ message: "Has bloqueado a este usuario." });
      const theyBlockedMe = await Block.findOne({ blockerId: otherUserId, blockedId: myId });
      if (theyBlockedMe) return res.status(403).json({ message: "Este usuario te ha bloqueado." });
    }

    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: "No se enviaron archivos." });
    }

    // Validación .exe
    const forbiddenExtensions = ['.exe', '.bat', '.sh', '.com', '.cmd', '.msi'];
    const hasForbidden = req.files.some(file => {
        const ext = file.originalname.toLowerCase().slice(file.originalname.lastIndexOf('.'));
        return forbiddenExtensions.includes(ext);
    });
    if (hasForbidden) return res.status(400).json({ message: "No se permiten archivos ejecutables (.exe)." });

    // 2. Subida a Cloudinary (Esto se mantiene igual, subimos todo junto para eficiencia)
    const uploadPromises = req.files.map(file => {
        return new Promise((resolve, reject) => {
            const isDocument = !file.mimetype.startsWith('image') && !file.mimetype.startsWith('video');
            let cleanName = file.originalname.replace(/\s+/g, "_").replace(/[^a-zA-Z0-9._-]/g, "");
            
            if (!isDocument) cleanName = cleanName.replace(/\.[^/.]+$/, "");
            
            const customPublicId = `${Date.now()}_${cleanName}`;

            const uploadStream = cloudinary.uploader.upload_stream(
                { 
                    folder: "nexo_chat_media",
                    resource_type: isDocument ? "raw" : "auto", 
                    public_id: customPublicId,
                },
                (error, result) => {
                    if (error) return reject(error);
                    resolve(result);
                }
            );
            uploadStream.end(file.buffer);
        });
    });

    const results = await Promise.all(uploadPromises);

    // 3. Crear mensajes separados (NUEVA LÓGICA)
    const createdMessages = [];
    
    // Preparamos la conversación para emitir actualización
    const populatedConv = await Conversation.findById(conversation._id)
        .populate('participants', 'username profilePictureUrl bio')
        .populate('groupAdmin', 'username')
        .populate('groupFounder', 'username');

    // Actualizar contadores de no leídos (sumamos la cantidad de archivos, no solo 1)
    conversation.deletedBy = [];
    conversation.participants.forEach(pId => {
      const pIdString = pId.toString();
      if (pIdString !== myId) {
          const socketId = userSocketMap[pId.toString()];
          const activeChatId = activeChatMap[socketId];
          // Si no está viendo el chat, aumentamos el contador por CADA archivo enviado
          if (activeChatId !== conversationId) {
              const currentCount = conversation.unreadCounts.get(pIdString) || 0;
              conversation.unreadCounts.set(pIdString, currentCount + results.length);
          }
      }
    });
    await conversation.save();

    // Bucle: Crear un mensaje por cada archivo subido
    for (const [index, result] of results.entries()) {
        let msgType = 'image';
        if (result.resource_type === 'video') msgType = 'video';
        if (result.resource_type === 'raw') msgType = 'mixed'; // Documentos

        // Si el usuario escribió texto, lo ponemos SOLO en el primer mensaje
        const msgContent = (index === 0) ? (content || '') : '';

        const newMessage = new Message({ 
            conversationId: conversationId, 
            sender: myId, 
            content: msgContent, 
            type: msgType,
            mediaUrls: [result.secure_url] // Solo una URL por mensaje
        });

        const savedMessage = await newMessage.save();
        const populatedMessage = await Message.findById(savedMessage._id).populate('sender', 'username profilePictureUrl');
        
        createdMessages.push(populatedMessage);

        // Emitir Socket por CADA mensaje
        conversation.participants.forEach(pId => {
            const socketId = userSocketMap[pId.toString()];
            if (socketId) {
                io.to(socketId).emit('newMessage', populatedMessage);
                // Enviamos actualización de la conversación solo en el último archivo para no saturar
                if (index === results.length - 1) {
                    io.to(socketId).emit('conversationUpdated', populatedConv);
                }
            }
        });
    }

    // Respondemos con el último mensaje creado (o podrías devolver el array)
    res.status(201).json(createdMessages[createdMessages.length - 1]);

  } catch (error) {
    console.error("Error en POST media:", error);
    res.status(500).json({ message: "Error al enviar archivos." });
  }
});

// 13. Búsqueda
app.get('/users/search', authMiddleware, async (req, res) => {
  try {
    const { query } = req.query;
    const myId = req.user.userId;
    if (!query) return res.json([]);
    const blocks = await Block.find({ $or: [{ blockerId: myId }, { blockedId: myId }] });
    const blockedIds = blocks.map(b => b.blockerId.toString() === myId ? b.blockedId.toString() : b.blockerId.toString());
    const users = await User.find({
      username: { $regex: query, $options: 'i' },
      _id: { $ne: myId, $nin: blockedIds }
    })
    .select('username profilePictureUrl bio');
    res.json(users);
  } catch (error) {
    console.error("Error en GET /users/search:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// 14. Borrar usuario
app.delete('/users/me', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const username = req.user.username;

    const userConversations = await Conversation.find({ participants: userId });

    for (const conv of userConversations) {
      if (conv.isGroup) {
        const newParticipants = conv.participants.filter(p => p.toString() !== userId);

        if (newParticipants.length === 0) {
          await Conversation.findByIdAndDelete(conv._id);
          await Message.deleteMany({ conversationId: conv._id });
        } else {
          conv.participants = newParticipants;
          let newAdmins = conv.groupAdmin.filter(id => id.toString() !== userId);
          
          if (conv.groupFounder && conv.groupFounder.toString() === userId) {
             if (newAdmins.length > 0) {
                conv.groupFounder = newAdmins[0];
             } else {
                conv.groupFounder = newParticipants[0];
                newAdmins.push(newParticipants[0]);
             }
          }
          if (newAdmins.length === 0 && newParticipants.length > 0) {
             newAdmins.push(newParticipants[0]);
          }
          conv.groupAdmin = newAdmins;
          await conv.save();

          const sysMsg = new Message({
            conversationId: conv._id,
            sender: null,
            type: 'system',
            content: `${username} eliminó su cuenta y salió del grupo.`
          });
          await sysMsg.save();

          const populatedGroup = await Conversation.findById(conv._id)
            .populate('participants', 'username profilePictureUrl bio')
            .populate('groupAdmin', 'username')
            .populate('groupFounder', 'username');

          newParticipants.forEach(pId => {
            const socketId = userSocketMap[pId.toString()];
            if (socketId) {
              io.to(socketId).emit('newMessage', sysMsg);
              io.to(socketId).emit('conversationUpdated', populatedGroup);
            }
          });
        }

      } else {
        const otherUserId = conv.participants.find(p => p.toString() !== userId);
        if (otherUserId) {
           const otherSocketId = userSocketMap[otherUserId.toString()];
           if (otherSocketId) {
              io.to(otherSocketId).emit('conversationDeleted', conv._id);
           }
        }
        await Conversation.findByIdAndDelete(conv._id);
        await Message.deleteMany({ conversationId: conv._id });
      }
    }

    await Message.deleteMany({ sender: userId });
    await User.findByIdAndDelete(userId);

    res.status(200).json({ message: "Cuenta de usuario y datos asociados eliminados." });

  } catch (error) {
    console.error("Error en DELETE /users/me:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// 15. RUTA PARA DESAGREGAR / SALIR DE GRUPO
app.delete('/conversations/:id', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const myId = req.user.userId;
    const myUsername = req.user.username;
    
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ message: "Conversación no encontrada." });
    }

    if (conversation.isGroup) {
      const newParticipants = conversation.participants.filter(p => p.toString() !== myId);

      if (newParticipants.length === 0) {
        await Conversation.findByIdAndDelete(conversationId);
        await Message.deleteMany({ conversationId: conversationId });
        return res.status(200).json({ message: "Grupo eliminado." });
      } 
      
      conversation.participants = newParticipants;
      let newAdmins = conversation.groupAdmin.filter(id => id.toString() !== myId);

      if (conversation.groupFounder && conversation.groupFounder.toString() === myId) {
         if (newAdmins.length > 0) {
            conversation.groupFounder = newAdmins[0];
         } else {
            conversation.groupFounder = newParticipants[0];
            newAdmins.push(newParticipants[0]); 
         }
      }

      conversation.groupAdmin = newAdmins;
      await conversation.save();

      const sysMsg = new Message({
        conversationId: conversationId,
        sender: null,
        type: 'system',
        content: `${myUsername} salió del grupo.`
      });
      await sysMsg.save();

      const populatedGroup = await Conversation.findById(conversationId)
        .populate('participants', 'username profilePictureUrl bio')
        .populate('groupAdmin', 'username')
        .populate('groupFounder', 'username');

      newParticipants.forEach(memberId => {
        const socketId = userSocketMap[memberId.toString()];
        if (socketId) {
          io.to(socketId).emit('newMessage', sysMsg);
          io.to(socketId).emit('conversationUpdated', populatedGroup);
        }
      });

      return res.status(200).json({ message: "Has salido del grupo." });

    } else {
      
      await Conversation.findByIdAndUpdate(conversationId, {
        $addToSet: { deletedBy: myId }
      });
      
      conversation.clearedHistoryAt.set(myId, Date.now());
      await conversation.save();

      const otherUserId = conversation.participants.find(p => p.toString() !== myId);
      if (otherUserId) {
          const socketId = userSocketMap[otherUserId.toString()];
          if (socketId) {
              io.to(socketId).emit('unfriendedBy', { 
                  unfrienderName: myUsername, 
                  unfrienderId: myId 
              });
          }
      }

      res.status(200).json({ message: "Usuario desagregado." });
    }

  } catch (error) {
    console.error("Error en DELETE /conversations/:id:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// 16. RUTA PARA MARCAR COMO LEÍDO
app.post('/conversations/:id/read', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const myId = req.user.userId;
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ message: "Conversación no encontrada." });
    }
    conversation.unreadCounts.set(myId, 0);
    await conversation.save();
    const populatedConv = await Conversation.findById(conversation._id)
        .populate('participants', 'username profilePictureUrl bio')
        .populate('groupAdmin', 'username')
        .populate('groupFounder', 'username');
    res.status(200).json(populatedConv);
  } catch (error) {
    console.error("Error en POST /conversations/:id/read:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// 17. RUTAS DE BLOQUEO

app.get('/users/me/blocked', authMiddleware, async (req, res) => {
  try {
    const myId = req.user.userId;
    const blocks = await Block.find({ blockerId: myId });
    const blockedIds = blocks.map(b => b.blockedId.toString());
    res.json(blockedIds);
  } catch (error) {
    console.error("Error en GET /users/me/blocked:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

app.post('/users/:id/block', authMiddleware, async (req, res) => {
  try {
    const myId = req.user.userId;
    const { id: blockedId } = req.params;
    if (myId === blockedId) {
      return res.status(400).json({ message: "No puedes bloquearte a ti mismo." });
    }
    const existingBlock = await Block.findOne({ blockerId: myId, blockedId: blockedId });
    if (existingBlock) {
      return res.status(200).json({ message: "Este usuario ya está bloqueado." });
    }
    
    const newBlock = new Block({
      blockerId: myId,
      blockedId: blockedId
    });
    await newBlock.save();

    // Notificar al bloqueado
    const blockedSocket = userSocketMap[blockedId];
    if (blockedSocket) {
      io.to(blockedSocket).emit('blockedBy', { 
        blockerId: myId,
        blockerName: req.user.username 
      });
    }

    res.status(201).json({ message: "Usuario bloqueado permanentemente." });
  } catch (error) {
    console.error("Error en POST /users/:id/block:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

app.delete('/users/:id/block', authMiddleware, async (req, res) => {
  try {
    const myId = req.user.userId;
    const { id: blockedId } = req.params;
    const deleted = await Block.findOneAndDelete({ blockerId: myId, blockedId: blockedId });
    if (!deleted) {
      return res.status(404).json({ message: "No tenías bloqueado a este usuario." });
    }

    // Notificar desbloqueo
    const blockedSocket = userSocketMap[blockedId];
    if (blockedSocket) {
      io.to(blockedSocket).emit('unblockedBy', { 
        blockerId: myId,
        blockerName: req.user.username 
      });
    }

    res.status(200).json({ message: "Usuario desbloqueado." });
  } catch (error) {
    console.error("Error en DELETE /users/:id/block:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

app.get('/users/:id/check-block', authMiddleware, async (req, res) => {
  try {
    const myId = req.user.userId;
    const { id: otherId } = req.params;

    const iBlockedThem = await Block.exists({ blockerId: myId, blockedId: otherId });
    const theyBlockedMe = await Block.exists({ blockerId: otherId, blockedId: myId });

    res.json({
      iBlockedThem: !!iBlockedThem,
      theyBlockedMe: !!theyBlockedMe
    });
  } catch (error) {
    console.error("Error en check-block:", error);
    res.status(500).json({ message: "Error" });
  }
});


// 18. RUTA PARA CREAR GRUPOS
app.post('/groups', authMiddleware, async (req, res) => {
  try {
    const { groupName, participants } = req.body;
    const myId = req.user.userId;
    if (!groupName || !participants || participants.length === 0) {
      return res.status(400).json({ message: "Faltan el nombre del grupo o los participantes." });
    }
    const allParticipants = [myId, ...participants];
    const unreadMap = new Map();
    allParticipants.forEach(pId => {
      unreadMap.set(pId.toString(), 0);
    });
    const newGroup = new Conversation({
      participants: allParticipants,
      initiatedBy: myId,
      status: 'active',
      isGroup: true,
      groupName: groupName,
      groupAdmin: [myId],
      groupFounder: myId, 
      unreadCounts: unreadMap,
      groupPictureUrl: DEFAULT_GROUP_PIC
    });
    await newGroup.save();

    const sysMsg = new Message({
        conversationId: newGroup._id,
        sender: null,
        type: 'system',
        content: `Grupo "${groupName}" creado por el Fundador.`
    });
    await sysMsg.save();

    const populatedGroup = await Conversation.findById(newGroup._id)
      .populate('participants', 'username profilePictureUrl bio')
      .populate('groupAdmin', 'username')
      .populate('groupFounder', 'username');

    allParticipants.forEach(memberId => {
      if (memberId.toString() !== myId) {
        const memberSocketId = userSocketMap[memberId.toString()];
        if (memberSocketId) {
          io.to(memberSocketId).emit('newGroupChat', populatedGroup);
        }
      }
    });
    res.status(201).json(populatedGroup);
  } catch (error) {
    console.error("Error en POST /groups:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// 19. RUTA PARA AÑADIR MIEMBROS
app.post('/groups/:id/add-members', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const { newMembers } = req.body;
    const myId = req.user.userId;
    const myUsername = req.user.username;

    if (!newMembers || newMembers.length === 0) {
      return res.status(400).json({ message: "No se seleccionaron miembros." });
    }
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.isGroup) {
      return res.status(404).json({ message: "Grupo no encontrado." });
    }
    
    const isAdmin = conversation.groupAdmin.some(adminId => adminId.toString() === myId);
    if (!isAdmin) {
      return res.status(403).json({ message: "No tienes permiso para añadir miembros." });
    }

    newMembers.forEach(pId => {
      if (!conversation.unreadCounts.has(pId.toString())) {
        conversation.unreadCounts.set(pId.toString(), 0);
      }
    });

    const updatedConversation = await Conversation.findByIdAndUpdate(
      conversationId,
      { 
        $addToSet: { participants: { $each: newMembers } },
        unreadCounts: conversation.unreadCounts
      },
      { new: true }
    )
    .populate('participants', 'username profilePictureUrl bio')
    .populate('groupAdmin', 'username')
    .populate('groupFounder', 'username');

    const addedUsers = await User.find({ _id: { $in: newMembers } });
    const names = addedUsers.map(u => u.username).join(", ");

    const sysMsg = new Message({
      conversationId: conversationId,
      sender: null,
      type: 'system',
      content: `${myUsername} añadió a: ${names}`
    });
    await sysMsg.save();

    updatedConversation.participants.forEach(participant => {
      const memberSocketId = userSocketMap[participant._id.toString()];
      if (memberSocketId) {
        if (newMembers.includes(participant._id.toString())) {
           io.to(memberSocketId).emit('newGroupChat', updatedConversation);
        } else {
           io.to(memberSocketId).emit('conversationUpdated', updatedConversation);
        }
        io.to(memberSocketId).emit('newMessage', sysMsg);
      }
    });

    res.status(200).json(updatedConversation);
  } catch (error) {
    console.error("Error en POST /groups/:id/add-members:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

// 20. RUTA PARA SUBIR FOTO DE PERFIL
app.post('/profile/upload', authMiddleware, upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No se subió ningún archivo." });
    }
    const myId = req.user.userId;
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { 
          folder: "nexo_profiles",
          public_id: myId,
          overwrite: true,
          format: "webp",
          width: 150,
          height: 150,
          crop: "fill",
          gravity: "face"
        },
        (error, result) => {
          if (error) return reject(error);
          resolve(result);
        }
      );
      uploadStream.end(req.file.buffer);
    });

    const user = await User.findById(myId);
    user.profilePictureUrl = result.secure_url;
    await user.save();

    res.status(200).json({ 
      message: "¡Foto de perfil actualizada!",
      profilePictureUrl: result.secure_url
    });

  } catch (error) {
    console.error("Error en POST /profile/upload:", error);
    res.status(500).json({ message: "Error al subir la imagen." });
  }
});

// 21. RUTA PARA GUARDAR BIO/USERNAME
app.put('/profile/update', authMiddleware, async (req, res) => {
  try {
    const { newUsername, newBio } = req.body;
    const myId = req.user.userId;

    if (newUsername !== req.user.username) {
      const existingUser = await User.findOne({ 
        username: { $regex: `^${newUsername}$`, $options: 'i' } 
      });
      if (existingUser) {
        return res.status(400).json({ message: "Ese nombre de usuario ya está en uso." });
      }
    }

    const user = await User.findByIdAndUpdate(
      myId,
      { 
        username: newUsername,
        bio: newBio 
      },
      { new: true }
    );

    io.emit('userProfileUpdated', {
      userId: user._id,
      username: user.username,
      bio: user.bio,
      profilePictureUrl: user.profilePictureUrl
    });

    const expiresIn = '1h';
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: expiresIn }
    );

    res.status(200).json({ 
      message: "Perfil actualizado.",
      newToken: token,
      username: user.username,
      bio: user.bio 
    });

  } catch (error) {
    console.error("Error en PUT /profile/update:", error);
    res.status(500).json({ message: "Error al guardar el perfil." });
  }
});

// 22. RUTAS PARA AJUSTES DE GRUPO
app.put('/groups/:id/details', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const { groupName } = req.body;
    const myId = req.user.userId;

    if (!groupName) {
      return res.status(400).json({ message: "El nombre del grupo no puede estar vacío." });
    }

    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.isGroup) {
      return res.status(404).json({ message: "Grupo no encontrado." });
    }

    const isAdmin = conversation.groupAdmin.some(adminId => adminId.toString() === myId);
    if (!isAdmin) {
      return res.status(403).json({ message: "No tienes permiso para editar este grupo." });
    }

    conversation.groupName = groupName;
    await conversation.save();
    
    const populatedGroup = await Conversation.findById(conversationId)
      .populate('participants', 'username profilePictureUrl bio')
      .populate('groupAdmin', 'username')
      .populate('groupFounder', 'username');
      
    populatedGroup.participants.forEach(p => {
      const socketId = userSocketMap[p._id.toString()];
      if (socketId) {
        io.to(socketId).emit('conversationUpdated', populatedGroup);
      }
    });

    res.status(200).json(populatedGroup);

  } catch (error) {
    console.error("Error en PUT /groups/:id/details:", error);
    res.status(500).json({ message: "Error al actualizar el grupo." });
  }
});

// 23. RUTA PARA HACER ADMIN A OTRO USUARIO
app.put('/groups/:id/promote', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const { memberId } = req.body; 
    const myId = req.user.userId;
    const myUsername = req.user.username;

    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.isGroup) {
      return res.status(404).json({ message: "Grupo no encontrado." });
    }

    const isMeAdmin = conversation.groupAdmin.some(adminId => adminId.toString() === myId);
    if (!isMeAdmin) {
      return res.status(403).json({ message: "No tienes permiso para hacer esto." });
    }

    const isAlreadyAdmin = conversation.groupAdmin.some(adminId => adminId.toString() === memberId);
    if (isAlreadyAdmin) {
      return res.status(400).json({ message: "Este usuario ya es administrador." });
    }

    conversation.groupAdmin.push(memberId);
    await conversation.save();

    const promotedUser = await User.findById(memberId);

    const sysMsg = new Message({
      conversationId: conversationId,
      sender: null,
      type: 'system',
      content: `${myUsername} ascendió a ${promotedUser.username} a Administrador.`
    });
    await sysMsg.save();

    const populatedGroup = await Conversation.findById(conversationId)
      .populate('participants', 'username profilePictureUrl bio')
      .populate('groupAdmin', 'username')
      .populate('groupFounder', 'username');

    populatedGroup.participants.forEach(p => {
      const socketId = userSocketMap[p._id.toString()];
      if (socketId) {
        io.to(socketId).emit('conversationUpdated', populatedGroup);
        io.to(socketId).emit('newMessage', sysMsg);
      }
    });

    res.status(200).json(populatedGroup);

  } catch (error) {
    console.error("Error en PUT /groups/:id/promote:", error);
    res.status(500).json({ message: "Error al promover usuario." });
  }
});

// 24. RUTA PARA QUITAR ADMIN (DEGRADAR)
app.put('/groups/:id/demote', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const { memberId } = req.body;
    const myId = req.user.userId;
    const myUsername = req.user.username;

    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.isGroup) {
      return res.status(404).json({ message: "Grupo no encontrado." });
    }

    // --- REGLA DE JERARQUÍA: SOLO EL FUNDADOR PUEDE DEGRADAR ---
    const isMeFounder = conversation.groupFounder && conversation.groupFounder.toString() === myId;

    if (!isMeFounder) {
      return res.status(403).json({ message: "Solo el Fundador puede quitar el rol de administrador." });
    }

    const isTargetAdmin = conversation.groupAdmin.some(adminId => adminId.toString() === memberId);
    if (!isTargetAdmin) {
      return res.status(400).json({ message: "Este usuario no es administrador." });
    }

    if (memberId === myId) {
      return res.status(400).json({ message: "No puedes quitarte el admin a ti mismo siendo Fundador." });
    }

    conversation.groupAdmin = conversation.groupAdmin.filter(adminId => adminId.toString() !== memberId);
    await conversation.save();

    const demotedUser = await User.findById(memberId);

    const sysMsg = new Message({
      conversationId: conversationId,
      sender: null,
      type: 'system',
      content: `${myUsername} (Fundador) degradó a ${demotedUser.username} a Miembro.`
    });
    await sysMsg.save();

    const populatedGroup = await Conversation.findById(conversationId)
      .populate('participants', 'username profilePictureUrl bio')
      .populate('groupAdmin', 'username')
      .populate('groupFounder', 'username');

    populatedGroup.participants.forEach(p => {
      const socketId = userSocketMap[p._id.toString()];
      if (socketId) {
        io.to(socketId).emit('conversationUpdated', populatedGroup);
        io.to(socketId).emit('newMessage', sysMsg);
      }
    });

    res.status(200).json(populatedGroup);

  } catch (error) {
    console.error("Error en PUT /groups/:id/demote:", error);
    res.status(500).json({ message: "Error al degradar usuario." });
  }
});

// 25. RUTA PARA EXPULSAR USUARIO (KICK)
app.put('/groups/:id/kick', authMiddleware, async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const { memberId } = req.body; 
    const myId = req.user.userId;
    const myUsername = req.user.username;

    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.isGroup) {
      return res.status(404).json({ message: "Grupo no encontrado." });
    }

    // 1. Validar permisos del que expulsa
    const isMeFounder = conversation.groupFounder && conversation.groupFounder.toString() === myId;
    const isMeAdmin = conversation.groupAdmin.some(id => id.toString() === myId);

    if (!isMeAdmin) { // (El fundador también está en groupAdmin)
        return res.status(403).json({ message: "No tienes permiso para expulsar." });
    }

    // 2. Validar rol del objetivo
    const isTargetFounder = conversation.groupFounder && conversation.groupFounder.toString() === memberId;
    const isTargetAdmin = conversation.groupAdmin.some(id => id.toString() === memberId);

    // 3. Aplicar Jerarquía
    if (isMeFounder) {
        if (memberId === myId) return res.status(400).json({ message: "No te puedes expulsar a ti mismo." });
        // Fundador puede expulsar a cualquiera (Admins o Miembros)
    } else if (isMeAdmin) {
        if (isTargetFounder) return res.status(403).json({ message: "Un Admin no puede expulsar al Fundador." });
        if (isTargetAdmin) return res.status(403).json({ message: "Un Admin no puede expulsar a otro Admin." });
        // Admin solo puede expulsar a Miembros normales
    }

    // 4. Ejecutar expulsión
    // Quitar de participantes
    conversation.participants = conversation.participants.filter(p => p.toString() !== memberId);
    
    // Quitar de admins (por si acaso el fundador está expulsando a un admin)
    if (isTargetAdmin) {
        conversation.groupAdmin = conversation.groupAdmin.filter(id => id.toString() !== memberId);
    }

    await conversation.save();

    const kickedUser = await User.findById(memberId);
    
    // Mensaje de sistema
    const sysMsg = new Message({
      conversationId: conversationId,
      sender: null,
      type: 'system',
      content: `${myUsername} expulsó a ${kickedUser.username}.`
    });
    await sysMsg.save();

    const populatedGroup = await Conversation.findById(conversationId)
      .populate('participants', 'username profilePictureUrl bio')
      .populate('groupAdmin', 'username')
      .populate('groupFounder', 'username');

    // Notificar a los que quedan
    populatedGroup.participants.forEach(p => {
        const socketId = userSocketMap[p._id.toString()];
        if (socketId) {
          io.to(socketId).emit('conversationUpdated', populatedGroup);
          io.to(socketId).emit('newMessage', sysMsg);
        }
    });
    
    // Notificar al expulsado (para que se le borre el chat)
    const kickedSocketId = userSocketMap[memberId];
    if (kickedSocketId) {
        io.to(kickedSocketId).emit('conversationUpdated', populatedGroup); 
    }

    res.status(200).json(populatedGroup);

  } catch (error) {
    console.error("Error en PUT /groups/:id/kick:", error);
    res.status(500).json({ message: "Error al expulsar usuario." });
  }
});

app.post('/groups/:id/avatar', authMiddleware, upload.single('groupPic'), async (req, res) => {
  try {
    const { id: conversationId } = req.params;
    const myId = req.user.userId;
    const myUsername = req.user.username;

    if (!req.file) {
      return res.status(400).json({ message: "No se subió ningún archivo." });
    }

    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.isGroup) {
      return res.status(404).json({ message: "Grupo no encontrado." });
    }
    
    // PERMISO: FUNDADOR O ADMIN
    const isAdmin = conversation.groupAdmin.some(adminId => adminId.toString() === myId);
    const isFounder = conversation.groupFounder && conversation.groupFounder.toString() === myId;

    if (!isAdmin && !isFounder) {
      return res.status(403).json({ message: "No tienes permiso para editar este grupo." });
    }

    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        { 
          folder: "nexo_groups",
          public_id: conversationId,
          overwrite: true,
          format: "webp",
          width: 150,
          height: 150,
          crop: "fill"
        },
        (error, result) => {
          if (error) return reject(error);
          resolve(result);
        }
      );
      uploadStream.end(req.file.buffer);
    });

    conversation.groupPictureUrl = result.secure_url;
    await conversation.save();

    // Mensaje de sistema
    const sysMsg = new Message({
      conversationId: conversationId,
      sender: null,
      type: 'system',
      content: `${myUsername} cambió la foto del grupo.`
    });
    await sysMsg.save();

    const populatedGroup = await Conversation.findById(conversationId)
      .populate('participants', 'username profilePictureUrl bio')
      .populate('groupAdmin', 'username')
      .populate('groupFounder', 'username');

    populatedGroup.participants.forEach(p => {
      const socketId = userSocketMap[p._id.toString()];
      if (socketId) {
        io.to(socketId).emit('conversationUpdated', populatedGroup);
        io.to(socketId).emit('newMessage', sysMsg);
      }
    });

    res.status(200).json(populatedGroup);

  } catch (error) {
    console.error("Error en POST /groups/:id/avatar:", error);
    res.status(500).json({ message: "Error al subir la imagen del grupo." });
  }
});


// 27. Encender el Servidor
const PORT = 5000;
server.listen(PORT, () => {
  console.log(`Servidor (y Socket.IO) corriendo en el puerto ${PORT}`);
});
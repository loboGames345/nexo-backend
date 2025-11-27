// models/Message.js

const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({

  // A qué conversación pertenece este mensaje
  conversationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Conversation'
  },

  // Quién envió este mensaje (Puede ser null si es mensaje del sistema)
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false 
  },

  // El contenido del mensaje
  content: {
    type: String,
    trim: true,
    default: ''
  },
  
  // Array para guardar URLs de fotos/videos
  mediaUrls: {
    type: [String],
    default: []
  },

  // Tipo de mensaje
  type: {
    type: String,
    enum: ['text', 'system', 'image', 'video', 'mixed'], 
    default: 'text'
  },

  // --- NUEVO: Bandera para saber si fue borrado ---
  isDeleted: {
    type: Boolean,
    default: false
  }

}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;
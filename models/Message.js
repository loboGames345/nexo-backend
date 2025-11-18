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
    required: true,
    trim: true
  },
  
  // --- NUEVO: Tipo de mensaje ---
  type: {
    type: String,
    enum: ['text', 'system'], // 'text' es normal, 'system' es aviso (azul/gris centrado)
    default: 'text'
  }

}, { timestamps: true });

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;
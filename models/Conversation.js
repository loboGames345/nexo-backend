// models/Conversation.js

const mongoose = require('mongoose');

const conversationSchema = new mongoose.Schema({
  
  participants: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  ],

  status: {
    type: String,
    enum: ['pending', 'active'],
    default: 'pending'
  },

  initiatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  // Si tu ID está aquí, el chat no te sale en la lista
  deletedBy: {
    type: [String],
    default: []
  },

  // --- NUEVO: Control de historial vacío ---
  // Guarda: { "userId": FechaDeLimpieza }
  // Si el usuario re-agrega, actualizamos esta fecha para que vea el chat "nuevo".
  clearedHistoryAt: {
    type: Map,
    of: Date,
    default: {}
  },

  isGroup: {
    type: Boolean,
    default: false
  },
  
  groupName: {
    type: String,
    trim: true
  },
  
  groupFounder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },

  groupAdmin: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  ],

  groupPictureUrl: {
    type: String,
    default: ''
  },
  
  unreadCounts: {
    type: Map,
    of: Number,
    default: {}
  },
  
  // --- NUEVO (Opcional): Bandera para saber si hay bloqueo visual ---
  // No es estrictamente necesaria si usamos la logica de index, 
  // pero ayuda si queremos persistir estados de UI.
  // Lo manejaremos dinámicamente en el index.js

}, { timestamps: true });

const Conversation = mongoose.model('Conversation', conversationSchema);

module.exports = Conversation;
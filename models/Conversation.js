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

  deletedBy: {
    type: [String],
    default: []
  },

  isGroup: {
    type: Boolean,
    default: false
  },
  
  groupName: {
    type: String,
    trim: true
  },
  
  // --- CAMBIO: Campo ÚNICO para el Fundador ---
  groupFounder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },

  // Lista de Administradores (El fundador TAMBIÉN estará aquí para facilitar permisos)
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
  }

}, { timestamps: true });

const Conversation = mongoose.model('Conversation', conversationSchema);

module.exports = Conversation;
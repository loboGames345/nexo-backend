// models/Block.js

const mongoose = require('mongoose');

// Este es el "molde" para un bloqueo temporal
const blockSchema = new mongoose.Schema({
  
  // Quién está haciendo el bloqueo
  blockerId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  
  // Quién está siendo bloqueado
  blockedId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  
  // --- ¡Magia de MongoDB! ---
  // Esto crea un "Índice TTL" (Time To Live).
  // MongoDB borrará automáticamente este documento 1 hora después
  // de que fue creado, levantando el bloqueo.
  createdAt: { 
    type: Date, 
    default: Date.now, 
    index: { expires: '1h' } // 1h = 1 hora
  }
});

const Block = mongoose.model('Block', blockSchema);

module.exports = Block;
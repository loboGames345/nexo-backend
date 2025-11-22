// models/Block.js

const mongoose = require('mongoose');

const blockSchema = new mongoose.Schema({
  blockerId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  blockedId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
    // SE ELIMINÓ LA LÍNEA: index: { expires: '1h' } 
    // Ahora el bloqueo es permanente.
  }
});

const Block = mongoose.model('Block', blockSchema);

module.exports = Block;
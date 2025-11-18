// models/User.js

const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  password: {
    type: String,
    required: true
  },
  
  profilePictureUrl: {
    type: String,
    default: ''
  },
  
  bio: {
    type: String,
    default: '¡Hola! Estoy usando Nexo.',
    maxLength: 150
  }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
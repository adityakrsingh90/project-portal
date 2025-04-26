const mongoose = require('mongoose');

const mentorSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  expertise: { 
    type: String
  },
  
  assignedProjects: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project' // Array of references to Project models assigned to this mentor
  }]
}, { timestamps: true });

const Mentor = mongoose.model('Mentor', mentorSchema);

module.exports = Mentor;
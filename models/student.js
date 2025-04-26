const mongoose = require('mongoose');

const studentSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  rollNo: {
    type: String,
    required: true,
    unique: true // Ensures roll numbers are unique in the database
  },
  course: {
    type: String,
    required: true
  },
  section: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true, // Ensures email addresses are unique
    lowercase: true, // Saves email in lowercase to avoid case sensitivity issues
    trim: true // Removes whitespace from both ends of a string
  },
  password: {
    type: String,
    required: true
  },
  assignedMentor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Mentor' // Reference to the Mentor model
  },
  appliedProjects: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project' // Array of references to Project models
  }],
  projectStatus: {
    type: Map, // Use a Map to store project ID and its status for the student
    of: String // The value in the Map will be the status (e.g., 'In Progress', 'Submitted')
  },
  profile: {
    // You can add more profile related fields here in the future
    type: Object
  }
}, { timestamps: true }); // Adds createdAt and updatedAt fields automatically

const Student = mongoose.model('Student', studentSchema);

module.exports = Student;
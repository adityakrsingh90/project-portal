const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true // Removes whitespace
  },
  description: {
    type: String,
    trim: true // Optional description
  },
  techStack: [{
    type: String,
    trim: true // Array of technologies used
  }],
  mentor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Mentor' // Reference to the Mentor model
  },
  studentsApplied: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Student' // Array of references to Student models who applied
  }],
  status: {
    type: String,
    enum: ['Pending', 'Approved', 'Rejected', 'Completed'],
    default: 'Pending'
  },
  submissions: [{
    studentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Student',
      required: true
    },
    files: [{
      type: String // Store file paths or URLs
    }],
    progressUpdates: [{
      date: { type: Date, default: Date.now },
      percentageCompletion: Number,
      milestones: String,
      comments: String
    }]
  }]
}, { timestamps: true });

const Project = mongoose.model('Project', projectSchema);

module.exports = Project;
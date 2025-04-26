const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
require('dotenv').config();

// Routes import
const adminRoutes = require('./routes/admin');
const studentRoutes = require('./routes/student');
const mentorRoutes = require('./routes/mentor');
const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');
console.log('swaggerJsDoc:', swaggerJsDoc);
const swaggerOptions = require('./swaggerOptions');
constswaggerDocs = swaggerJsDoc(swaggerOptions);
const swaggerDocs = swaggerJsDoc(swaggerOptions);

// Middleware
app.use(cors());
app.use(helmet()); // Use Helmet to secure HTTP headers
app.use(express.json()); // For JSON request bodies
app.use(express.urlencoded({ extended: false })); // For URL-encoded request bodies
// app.use(mongoSanitize()); // Apply mongo sanitize with default settings
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs)); // Swagger UI setup - Corrected path

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: 'Too many requests from this IP, please try again after 15 minutes',
});
app.use(limiter); // Apply to all routes

// Use routes
app.use('/api/admin', adminRoutes);
app.use('/api/students', studentRoutes);
app.use('/api/mentors', mentorRoutes);

// Error handling middleware
const errorHandler = require('./middleware/error-handler');
app.use(errorHandler);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('Could not connect to MongoDB:', err));

// Import Project model
const Project = require('./models/project');

// Temporary code for explain
async function analyzeProjectQuery() {
  try {
    const projectsQuery = Project.find().populate('mentor', 'name email');
    const explaination = await projectsQuery.explain();
    console.log('Explain for /api/admin/projects (no filter):', explaination);
  } catch (error) {
    console.error('Error explaining query:', error);
  }
}

analyzeProjectQuery();
// End of temporary code

const bcrypt = require('bcrypt');

async function generateHash(password) {
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Hashed Password:', hashedPassword);
    return hashedPassword;
  } catch (error) {
    console.error('Error hashing password:', error);
    return null;
  }
}

generateHash('secure123');

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
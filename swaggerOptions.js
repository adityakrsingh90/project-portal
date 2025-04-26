const swaggerDefinition = {
    openapi: '3.0.0',
    info: {
        title: 'Your Project API',
        version: '1.0.0',
        description: 'Documentation for your project API',
    },
    servers: [
        {
            url: 'http://localhost:3000/api',
            description: 'Development server',
        },
    ],
    components: {
        securitySchemes: {
            BearerAuth: {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT',
            },
        },
    },
    tags: [
        { name: 'Student', description: 'Operations related to students' },
        { name: 'Mentor', description: 'Operations related to mentors' },
        { name: 'Admin', description: 'Admin-related operations' },
    ],
};

module.exports = {
  swaggerDefinition,
  apis: ['./routes/admin.js', './routes/student.js', './routes/mentor.js'], // Apne route files ke paths yahan dein
  tags: [],
};
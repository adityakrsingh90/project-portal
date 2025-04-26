// middleware/error-handler.js

const errorHandler = (err, req, res, next) => {
    console.error(err.stack); // Log the error stack for debugging
  
    const statusCode = res.statusCode === 200 ? 500 : res.statusCode; // Use existing status code or default to 500
    res.status(statusCode).json({
      message: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined, // Show stack only in development
    });
  };
  
  module.exports = errorHandler;
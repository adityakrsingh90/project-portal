const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  const token = authHeader.split(' ')[1]; // Extract the token after "Bearer "

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.user = decoded; // Attach user information to the request object
    next(); // Pass control to the next middleware function
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

const authorize = (roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Access denied. Unauthorized role.' });
  }
  next();
};

module.exports = { authenticate, authorize };
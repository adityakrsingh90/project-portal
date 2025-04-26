const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticate, authorize } = require('../middleware/auth');

// Fixed admin credentials
const ADMIN_EMAIL = 'admin@example.com';
const ADMIN_PASSWORD = 'adminpassword';

// Admin Login Route (as before)
router.post('/login', async (req, res) => {
  // ... (same login logic as before)
});

// Example protected admin route
router.get('/dashboard', authenticate, authorize(['admin']), (req, res) => {
  res.json({ message: 'Admin dashboard accessed successfully!', user: req.user });
});

module.exports = router;
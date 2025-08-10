// index.js
const winston = require('winston');

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const secretKey = 'yourSecretKey'; // Replace with your own secret key

app.use(express.json());

// Sample user data (Replace with your database or actual authentication logic)
const users = [];

const logger = winston.createLogger({
  level: 'info', // Log level
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ), // Log format
  transports: [
    // Console transport
    new winston.transports.Console(),
    // File transport
    new winston.transports.File({ filename: 'logfile.log' }),
  ],
});

// Endpoint for user registration
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Check if the username already exists
  const existingUser = users.find((u) => u.username === username);
  logger.info("Attempting to register user: " + username);
if (existingUser) {
  logger.error("Username already exists");
  logger.warn("Please choose a different username.");
  return res.status(400).json({ message: 'Username already exists' });
}


  // Add new user to the database
  const newUser = {
    id: users.length + 1,
    username,
    password,
  };
  users.push(newUser);

  res.status(201).json({ message: 'User registered successfully' });
  logger.info("User registered successfully: " + username);
});

// Endpoint for user login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Find user by username and password
  const user = users.find((u) => u.username === username && u.password === password);

  if (user) {
    // User authenticated, generate token
    const token = jwt.sign({ id: user.id, username: user.username }, secretKey);
    logger.info("User logged in successfully: " + username);
    res.json({ token });
  } else {
    logger.error("Invalid login attempt for user: " + username);
    logger.warn("Please check your credentials and try again. "+ username);
    res.status(401).json({ message: 'Invalid username or password'});
  }
});

// Protected route example (Dashboard access)
app.get('/dashboard', verifyToken, (req, res) => {
  // Return dashboard data or user-specific information
  res.json({ message: 'Welcome to the Customer Portal!' });
});

// Middleware to verify token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (typeof token !== 'undefined') {
    jwt.verify(token, secretKey, (err, authData) => {
      if (err) {
        res.sendStatus(403);
      } else {
        req.authData = authData;
        next();
      }
    });
  } else {
    logger.error("No token provided");
    logger.warn("Authorization token is required.");
    res.sendStatus(403);
  }
}

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
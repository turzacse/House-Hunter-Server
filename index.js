require('dotenv').config();
const express = require('express');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;
const secretKey = process.env.JWT_SECRET;

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
});

async function startServer() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');

    const db = client.db('House-Hunter');
    const usersCollection = db.collection('users');

    app.get('/users', async (req, res) => {
        try {
          // Retrieve all users from the users collection
          const allUsers = await usersCollection.find().toArray();
      
          // Respond with the array of user documents
          res.json(allUsers);
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Internal server error', error: error.message });
        }
      });
    // Registration endpoint
    app.post('/register', async (req, res) => {
        try {
          const { fullName, role, phoneNumber, email, password } = req.body;
      
          // Check if the email already exists
          const existingUser = await usersCollection.findOne({ email });
      
          if (existingUser) {
            // Email already exists, return an error response
            return res.status(400).json({ message: 'Email already exists' });
          }
      
          // Hash the password
          const hashedPassword = await bcrypt.hash(password, 10);
      
          // Create a new user document
          const newUser = {
            fullName,
            role,
            phoneNumber,
            email,
            password: hashedPassword,
          };
      
          // Insert the new user document into the users collection
          await usersCollection.insertOne(newUser);
      
          // Respond with a success message
          res.status(201).json({ message: 'User registered successfully' });
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: 'Internal server error', error: error.message });
        }
      });

    // Login endpoint
    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;

        // Find the user by email
        const user = await usersCollection.findOne({ email });

        // If user not found or password doesn't match, return an error
        if (!user || !(await bcrypt.compare(password, user.password))) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate a JWT token
        const token = jwt.sign({ email: user.email, role: user.role }, secretKey, { expiresIn: '1h' });

        // Respond with the JWT token
        res.json({ token });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
      }
    });

    // Protected route example
    app.get('/protected', authenticateJWT, (req, res) => {
      res.json({ message: 'This is a protected route', user: req.user });
    });

    // Start the server
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
  }
}

async function stopServer() {
  try {
    await client.close();
    console.log('Disconnected from MongoDB');
  } catch (error) {
    console.error('Error closing MongoDB connection:', error);
  }
}

function authenticateJWT(req, res, next) {
  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ message: 'Missing token' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }

    req.user = user;
    next();
  });
}
app.get('/', (req, res) => {
    res.send('Server is running');
  });
// Start the server
startServer();

// Handle process termination (e.g., Ctrl+C) to close the MongoDB connection
process.on('SIGINT', async () => {
  await stopServer();
  process.exit(0);
});

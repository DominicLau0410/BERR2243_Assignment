// Load environment variables from .env file
require('dotenv').config();

// Import express
const express = require('express')

// Initialize Express app
const app = express()

// Middleware to parse incoming JSON requests
app.use(express.json())

// Connect to mongoDB
const { connectToMongoDB} = require('./db');
connectToMongoDB();

// Import routes modules
const usersRoutes = require('./routes/users');
const driversRoutes = require('./routes/drivers');
const ridesRoutes = require('./routes/rides');
const adminsRoutes = require('./routes/admins');

// Register application routes
app.use('/users', usersRoutes);
app.use('/drivers', driversRoutes);
app.use('/rides', ridesRoutes);
app.use('/admins', adminsRoutes);

// Server port (use environment variable)
const port = process.env.PORT;

// Server setup
app.listen(port, () => {
    console.log(`Server running on port ${port}`)
})
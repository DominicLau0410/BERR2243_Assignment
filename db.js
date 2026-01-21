/**
 * db.js
 * MongoDB connection
 */

// Import module to access mongoDB
const { MongoClient } = require('mongodb');

// Declare a global variable to hold the MongoDB database instance
let db;

/**
 * Connects to MongoDB and initializes the global database instance.
 * This function is executed once when the server starts.
 */
async function connectToMongoDB() {
    // MongoDB connection URI from environment variable or fallback to local
    const uri = process.env.MONGO_URI;

    // Create a new MongoClient instance
    const client = new MongoClient(uri);
    
    // Record start time to calculate connection duration
    const startTime = Date.now();

    // Attempt to connect to MongoDB
    await client.connect();

    // Calculate the duration of connection to MongoDB
    const duration  = Date.now() - startTime;
    console.log(`Connected to MongoDB! (${duration} ms)`);

    // Select database
    db = client.db(process.env.DB_NAME);
}


/**
 * Get the DB object
 */
function getDB() {
    if (!db) throw new Error('Database not connected. Call Connect to MongoDB first.');
    return db;
}

// Export function
module.exports = {
    connectToMongoDB,
    getDB,
};
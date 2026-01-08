// ==========================
// Module Imports
// ==========================
const express = require('express')
const { MongoClient, ObjectId } = require('mongodb');

// Import modules for password hashing and authentication
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Load environment variables from .env file
require('dotenv').config();


// ==========================
// Authentication Middleware
// ==========================

/**
 * Middleware to verify JWT token from the Authorization header.
 * If valid, attaches decoded payload to req.auth.
 * Returns 401 Unauthorized if token is missing or invalid.
 */
const authenticate = (req, res, next) => {
    // Get token from "Authorization: Bearer <token>"
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    // If no token is provided, deny access
    if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        // Verify JWT and decode payload
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Attach decoded info to request object for downstream use
        req.auth = decoded;   // { userId, role }
        next();
    } catch (err) {
        return res.status(401).json({ error: "Invalid token" });
    }
};

/**
 * Middleware factory for role-based authorization.
 * Returns 403 Forbidden if the user's role is not in the allowed list.
 */
const authorize = (roles) => {
    return (req, res, next) => {
        // req.auth is set by authenticate middleware (userId, role)
        if (!req.auth || !roles.includes(req.auth.role)) {
            return res.status(403).json({ error: "Forbidden" });
        }
        next();
    };
};

// ==========================
// App Configuration
// ==========================

// Server port (use environment variable or fallback to 3000)
const port = process.env.PORT;

// Initialize Express app
const app = express()

// Middleware to parse incoming JSON requests
app.use(express.json())

// Declare a global variable to hold the MongoDB database instance
let db;

// Define the number of salt rounds for bcrypt hashing (recommended range: 10–12)
const saltRounds = 10;


// ==========================
// Database Connection
// ==========================

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

    try {
        // Attempt to connect to MongoDB
        await client.connect();

        // Calculate the duration of connection to MongoDB
        const duration  = Date.now() - startTime;
        console.log(`Connected to MongoDB! (${duration} ms)`);
    
        // Select database
        db = client.db(process.env.DB_NAME);
    } catch (err) {
        // Log any connection errors
        console.error("Error:", err);
    }
}

// Initialize database connection
connectToMongoDB();


// ==========================
// Server Startup
// ==========================
app.listen(port, () => {
    console.log(`Server running on port ${port}`)
})


// ==========================
// Constants (Enum-like)
// ==========================

const ROLES = Object.freeze({
    USER: "user",
    DRIVER: "driver",
    ADMIN: "admin"
});

const PAYMENT_METHOD = Object.freeze({
    CASH: "cash",
    BANK: "bank",
    CREDIT_CARD: "credit_card"
});

const ACCOUNT_STATUS = Object.freeze({
    ACTIVE: "active",
    DEACTIVE: "deactive"
});

const BOOKING_STATUS = Object.freeze({
    REQUESTED: "requested",
    ACCEPTED: "accepted",
    CANCELLED: "cancelled",
});


// ==========================
// Function
// ==========================

/**
 * Check if a entity is active
 * Return true if active, false otherwise
 */
function checkStatus(entity, expectedStatus) {
    if (!entity || !expectedStatus) return false;
    return entity.status === expectedStatus;
}

// ==========================
// User
// ==========================

/**
 * POST /users/register
 * Registers a new user and stores a hashed password in the database.
 */
app.post('/users/register', async (req, res) => {
    try {
        const collection = "users";

        // Destructure user input from request body
        const { username, phone, email, password, preferPay, bankAccountNumber} = req.body;

        if (!username || !phone || !email || !password || !preferPay) {
            return res.status(400).json({ error: "Missing information." });
        }

        // Check the validity of payment method
        if (!Object.values(PAYMENT_METHOD).includes(preferPay)) {
            return res.status(400).json({
                error: "Invalid payment method"
            });
        }
        
        // Check whether the email already exists in the database
        const existingAcc = await db.collection(collection).findOne({ email: email });
        if (existingAcc) {
            return res.status(409).json({ error: "Account already registered." });
        }

        // Hash the password before storing it to prevent plaintext password leaks
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Prepare New user object to insert into database
        const newAccount = {
            role : ROLES.USER,
            username,
            phone,
            email,
            password: hashedPassword,
            preferPay,
            bankAccountNumber : bankAccountNumber || null,
            createdAt: new Date(),
            status : ACCOUNT_STATUS.ACTIVE
        };

        // Insert new user document into MongoDB
        const result = await db.collection(collection).insertOne(newAccount);

        // Return success response with minimal user info (without password)
        return res.status(201).json({
            message: `User registered successfully`,
            id: result.insertedId,
            username,
            email
        });

    } catch (err) {
        console.error("Register Error:", err);
        res.status(500).json({ error: "Registration failed." });
    }
});

/**
 * POST /users/login
 * Authenticates user credentials and returns a JWT token.
 */
app.post('/users/login', async (req, res) => {
    try {
        const collection = "users";
        const { email, password } = req.body;
        
        // Validate required fields
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required." });
        }

        // Check whether the email already exists in the database
        const existingUser = await db.collection(collection).findOne({ email: email });
        if (!existingUser) {
            return res.status(404).json({ error: "User not registered." });
        }

        // Check the exixting account status whether active or deactive
        if (!checkStatus(existingUser, ACCOUNT_STATUS.ACTIVE)) {
            return res.status(403).json({ error: "Account not active" });
        }

        // Compare the input password with the hashed password stored in the database
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        // Generate JWT for authenticated user
        const token = jwt.sign(
            {   userId: existingUser._id, 
                role: existingUser.role 
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN}
        );

        // Successful login response with return token
        return res.status(200).json({
            message: "Login successful",
            token,
            user: {
                id: existingUser._id,
                username: existingUser.username,
                email: existingUser.email,
                phone: existingUser.phone
            }
        });

    } catch (err) {
        console.error("Login Error:", err);
        return res.status(500).json({ error: "Failed to login." });
    }
});

/** 
 * This system uses stateless JWT authentication.
 * Authentication state is not stored on the server.
 * When a user logs out, the client simply removes the JWT token,
 * and subsequent requests will be unauthorized.
 * Hence, a logout API is not implemented.
*/

/**
 * GET /users/profile/:id
 * Retrieves the profile of the authenticated user.
 */
app.get('/users/profile/:id', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
        const collection = "users";
        const userId = req.params.id; // userId from req.params.id in the string form

        // Ensure the authenticated user can only access their own profile
        if (req.auth.userId !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        // Find user profile while excluding sensitive fields
        const user = await db.collection(collection).findOne(
            { _id: new ObjectId(userId) },
            { projection: { password: 0 } }
        );

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
            message: "User profile retrieved successfully",
            user
        });

    } catch (err) {
        console.error("View Profile Error:", err);
        return res.status(500).json({ error: "Failed to retrieve profile" });
    }
});

/**
 * PATCH /users/profile/:id
 * Update the profile of the authenticated user.
 */
app.patch('/users/profile/:id', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
        const collection = "users";
        const userId = req.params.id;

        if (req.auth.userId !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        // Fix the field that allow to update
        const allowedFields = [
            "username",
            "phone",
            "preferPay",
            "bankAccountNumber"
        ];

        const updateData = {};

        // Filter valid update field from request body
        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updateData[field] = req.body[field];
            }
       }

       // Check the validity of payment method
       if (
            req.body.preferPay &&
            !Object.values(PAYMENT_METHOD).includes(req.body.preferPay)
        ) {
            return res.status(400).json({
                error: "Invalid payment method"
            });
        }

       // No update process when the updateData is empty
       if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No valid fields provided for update" });
        }

        const result = await db.collection(collection).updateOne(
            { _id: new ObjectId(userId) },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
            message: "Profile updated successfully",
            updatedFields: updateData
        });

    } catch (err) {
        console.error("Update Profile Error:", err);
        return res.status(500).json({ error: "Failed to update profile" });
    }
});

// TODO : delete account by using PATCH to deactive status

/**
 * POST /users/booking
 * Create new car booking.
 */
app.post('/users/booking', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
        const collection = "bookings";
        const { pickupLocation, dropoffLocation, vehicleRequested } = req.body;
        
        const userId = new ObjectId(req.auth.userId); // Save the userId in ObjectId form
        const estimatedDistance = 10; // Temporary fixed distance (10 km).
        const estimatedFare = 4.1 + (estimatedDistance * 2);

        // Validate required fields
        if (!pickupLocation || !dropoffLocation) {
            return res.status(400).json({ error: "Missing information." });
        }
        // Prepare booking detail to insert into database
        const bookingDetail = {
            userId : userId,
            pickupLocation,
            dropoffLocation,
            vehicleRequested : vehicleRequested || null,
            estimatedDistance : estimatedDistance,
            estimatedFare : estimatedFare,
            createdAt : new Date(),
            status : "requested" // Status selection: requested / accepted / cancelled
        };

        // Insert booking into MongoDB
        const result = await db.collection(collection).insertOne(bookingDetail);

        return res.status(201).json({
            message: `Booking successfully`,
            bookingId: result.insertedId,
        });

    } catch (err) {
        console.error("Create Booking Error:", err);
        return res.status(500).json({ error: "Failed to create booking" });
    }
});

/**
 * GET /users/booking/:id
 * View booking detail (user only).
 */
app.get('/users/booking/:id', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
      const bookingId = req.params.id;
      const userId = new ObjectId(req.auth.userId);

      const booking = await db.collection('bookings').findOne({
        _id: new ObjectId(bookingId),
        userId: userId
      });

      if (!booking) {
        return res.status(404).json({
          error: "Booking not found or access denied"
        });
      }

      return res.status(200).json({
        message: "Booking retrieved successfully",
        booking
      });

    } catch (err) {
      console.error("View Booking Error:", err);
      return res.status(500).json({
        error: "Failed to retrieve booking"
      });
    }
  }
);

/**
 * PATCH /users/booking/:id
 * Update the booking detail
 */
app.patch('/users/profile/:id', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
        const collection = "users";
        const userId = req.params.id;

        if (req.auth.userId !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        // Fix the field that allow to update
        const allowedFields = [
            "username",
            "phone",
            "preferPay",
            "bankAccountNumber"
        ];

        const updateData = {};

        // Filter valid update field from request body
        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updateData[field] = req.body[field];
            }
       }

       // Check the validity of payment method
       if (
            req.body.preferPay &&
            !Object.values(PAYMENT_METHOD).includes(req.body.preferPay)
        ) {
            return res.status(400).json({
                error: "Invalid payment method"
            });
        }

       // No update process when the updateData is empty
       if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No valid fields provided for update" });
        }

        const result = await db.collection(collection).updateOne(
            { _id: new ObjectId(userId) },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
            message: "Profile updated successfully",
            updatedFields: updateData
        });

    } catch (err) {
        console.error("Update Profile Error:", err);
        return res.status(500).json({ error: "Failed to update profile" });
    }
});
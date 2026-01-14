// ==========================
// Module Imports
// ==========================
const express = require('express')
const { MongoClient, ObjectId } = require('mongodb');

// Import modules for password hashing and authentication
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Verify } = require('crypto');

// Load environment variables from .env file
require('dotenv').config();


// ==========================
// Authentication Middleware
// ==========================

/**
 * Middleware to verify JWT token from the Authorization header.
 * If valid, attaches decoded payload to req.auth.id
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

        req.auth = {
            id: decoded.id,
            role: decoded.role
        };

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
        // req.auth is set by authenticate middleware (id, role)
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

const PAYMENT_STATUS = Object.freeze({
    PENDING: "pending",
    SUCCESS: "success"
});

const ACCOUNT_STATUS = Object.freeze({
    ACTIVE: "active",
    DEACTIVE: "deactive",
    SUSPENDED: "suspended"
});

const RIDE_STATUS = Object.freeze({
    REQUESTED: "requested",
    ACCEPTED: "accepted",
    ONGOING: "on going",
    COMPLETED: "completed",
    CANCELLED: "cancelled"
});

const VEHICLE_STATUS = Object.freeze({
    ACTIVE: "active",
    INACTIVE: "inactive",
    SUSPENDED: "suspended"
});

const VEHICLE_TYPE = Object.freeze({
    CAR_4P: "4 people car",
    CAR_6P: "6 people car",
    MOTOR: "motor",
    VAN: "van"
});


// ==========================
// Function
// ==========================

// TODO : Registration & Login function to all roles

/**
 * Check if a entity is active
 * Return true if active, false otherwise
 */
function checkStatus(entity, expectedStatus) {
    if (!entity || !expectedStatus) return false;
    return entity.status === expectedStatus;
}

// ==========================
// USER
// ==========================

/**
 * POST /users/register
 * Registers a new user and stores a hashed password in the database.
 */
app.post('/users/register', async (req, res) => {
    try {
        const collection = "users";

        // Destructure user input from request body
        const { username, phone, email, password, preferPay, bankAccountNumber } = req.body;

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
        const existingAcc = await db.collection(collection).findOne({ email: email });
        if (!existingAcc) {
            return res.status(404).json({ error: "User not registered." });
        }

        // Check the exixting account status whether active or deactive
        if (!checkStatus(existingAcc, ACCOUNT_STATUS.ACTIVE)) {
            return res.status(403).json({ error: "Account not active" });
        }

        // Compare the input password with the hashed password stored in the database
        const isMatch = await bcrypt.compare(password, existingAcc.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        // Generate JWT for authenticated user
        const token = jwt.sign(
            {
                id: existingAcc._id.toString(),
                role: existingAcc.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        // Successful login response with return token
        return res.status(200).json({
            message: "Login successful",
            token,
            user: {
                id: existingAcc._id,
                username: existingAcc.username,
                email: existingAcc.email,
                phone: existingAcc.phone
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
        if (req.auth.id !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        // Find user profile while excluding sensitive fields
        const user = await db.collection(collection).findOne(
            { _id: new ObjectId(userId) },
            { projection: { password: 0 } } // Ignore the password for security
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

        if (req.auth.id !== userId) {
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
        const { pickupLocation, dropoffLocation, requestedVehicleType } = req.body;
        
        const userId = new ObjectId(req.auth.id); // Save the id in ObjectId form
        const estimatedDistance = 10; // Temporary fixed distance (10 km).
        const estimatedFare = 4.1 + (estimatedDistance * 2);

        // Validate required fields
        if (!pickupLocation || !dropoffLocation || !requestedVehicleType) {
            return res.status(400).json({ error: "Missing information." });
        }

        // Check the validity of vehicle tye
        if (!Object.values(VEHICLE_TYPE).includes(requestedVehicleType)) {
            return res.status(400).json({
                error: "Invalid vehicle type."
            });
        }

        // Prepare booking detail to insert into database
        const bookingDetail = {
            userId : userId,
            pickupLocation,
            dropoffLocation,
            requestedVehicleType : requestedVehicleType || null,
            estimatedDistance : estimatedDistance,
            estimatedFare : estimatedFare,
            createdAt : new Date(),
            status : RIDE_STATUS.REQUESTED // Status selection: requested / accepted / cancelled
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
        const collection = "bookings";
        const bookingId = req.params.id;
        const userId = new ObjectId(req.auth.id);
        
        const booking = await db.collection(collection).findOne({
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
});

/**
 * PATCH /users/booking/:id
 * Update the booking detail
 */
app.patch('/users/booking/:id', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
        const collection = "bookings";
        const bookingId = req.params.id;
        const userId = new ObjectId(req.auth.id);

        // Fix the field that allow to update
        const allowedFields = [
            "pickupLocation",
            "dropoffLocation",
            "requestedVehicleType"
        ];

        const updateData = {};

        // Check the validity of vehicle type
        if (
            req.body.requestedVehicleType &&
            !Object.values(VEHICLE_TYPE).includes(req.body.requestedVehicleType)
        ) {
            return res.status(400).json({
                error: "Invalid vehicle type."
            });
        }

        // Filter valid update field from request body
        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updateData[field] = req.body[field];
            }
        };

        // No update process when the updateData is empty
        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No valid fields provided for update" });
        }

        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(bookingId),
                userId: userId,
                status: RIDE_STATUS.REQUESTED
            },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Booking not found" });
        }

        return res.status(200).json({
            message: "Booking updated successfully",
            updatedFields: updateData
        });

    } catch (err) {
        console.error("Update Booking Error:", err);
        return res.status(500).json({ error: "Failed to update booking" });
    }
});

/**
 * PATCH /users/booking/:id/cancel
 * Cancel the booking with PATCH Request to update status without delete the history of booking
 */
app.patch('/users/booking/:id/cancel', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
        const collection = "bookings";
        const bookingId = req.params.id;
        const userId = new ObjectId(req.auth.id);

        const updateData = {
            status : RIDE_STATUS.CANCELLED,
            cancelledAt : new Date()
        }

        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(bookingId),
                userId: userId,
                status: RIDE_STATUS.REQUESTED
            },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Booking not found." });
        }

        return res.status(200).json({
            message: "Booking cancelled successfully",
            bookingId: bookingId,
            status: RIDE_STATUS.CANCELLED
        });
    } catch (err) {
        console.error("Cancel Booking Error:", err);
        return res.status(500).json({ error: "Failed to cancel booking" });
    }
});

/**
 * PATCH /users/ride/:id/payment
 * User pay after ride completed.
 */
app.patch('/users/ride/:id/payment', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
        const collection = "payments";
        const rideId = new ObjectId(req.params.id);
        const userId = new ObjectId(req.auth.id);

        const { paymentMethod, transactionReferences } = req.body;

        if (!paymentMethod || !transactionReferences) {
            return res.status(400).json({ error: "Missing information." });
        }

        if (!Object.values(PAYMENT_METHOD).includes(paymentMethod)) {
            return res.status(400).json({
                error: "Invalid payment method."
            });
        }

        const updateData = {
            paymentMethod,
            transactionReferences,
            status : PAYMENT_STATUS.SUCCESS,
            paidAt : new Date()
        }

        const result = await db.collection(collection).updateOne(
            {
                rideId: rideId,
                userId: userId,
                status: PAYMENT_STATUS.PENDING
            },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Payment not found." });
        }

        return res.status(200).json({
            message: "Payment successfully",
            rideId: rideId,
            status: PAYMENT_STATUS.SUCCESS
        });
    } catch (err) {
        console.error("Payment Error:", err);
        return res.status(500).json({ error: "Failed to pay." });
    }
});

/**
 * POST /users/ride/:id/rating
 * User rates a completed ride.
 */
app.post('/users/ride/:id/rating', authenticate, authorize([ROLES.USER]), async (req, res) => {
    try {
        const ridesCollection = "rides";
        const ratingsCollection = "ratings";
        const driversCollection = "drivers";

        const rideId = new ObjectId(req.params.id);
        const userId = new ObjectId(req.auth.id);

        const { rating, comment } = req.body;

        if (!Number.isInteger(rating) || rating < 1 || rating > 5 ) {
            return res.status(400).json({
                error: "Rating must be an integer between 1 and 5."
            });
        }

        const ride = await db.collection(ridesCollection).findOne({
            _id: rideId,
            userId: userId,
            status: RIDE_STATUS.COMPLETED
        });

        if (!ride) {
            return res.status(404).json({
                error: "Ride not found, not completed, or access denied."
            });
        }

        const existingRating = await db.collection(ratingsCollection).findOne({
            rideId: rideId,
            userId: userId
        });

        if (existingRating) {
            return res.status(400).json({ error: "This ride has already been rated." });
        }

        await db.collection(ratingsCollection).insertOne({
            rideId,
            userId,
            driverId: ride.driverId,
            rating,
            comment: comment || null,
            createdAt: new Date()
        });

        // Updated the rating of driver in drivers collection
        await db.collection(driversCollection).updateOne(
            { _id: ride.driverId },
            {
                $inc: {
                    ratingCount: 1,
                    ratingSum: rating
                }
            }
        );

        return res.status(201).json({
            message: "Rating submitted successfully",
            rating
        });

    } catch (err) {
        console.error("Create Rating Error:", err);
        return res.status(500).json({ error: "Failed to submit rating." });
    }
});


// ==========================
// DRIVER
// ==========================

/**
 * POST /drivers/register
 * Registers a new driver and stores a hashed password in the database.
 */
app.post('/drivers/register', async (req, res) => {
    try {
        const collection = "drivers";

        // Destructure user input from request body
        const { username, phone, email, password, licenseNumber, licenseExpiry, bankAccountNumber } = req.body;

        if (!username || !phone || !email || !password || !licenseNumber || !licenseExpiry) {
            return res.status(400).json({ error: "Missing information." });
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
            role : ROLES.DRIVER,
            username,
            phone,
            email,
            password: hashedPassword,
            licenseNumber,
            licenseExpiry,
            bankAccountNumber : bankAccountNumber || null,
            ratingSum : 0,
            ratingCount : 0,
            createdAt: new Date(),
            status : ACCOUNT_STATUS.ACTIVE
        };

        // Insert new driver document into MongoDB
        const result = await db.collection(collection).insertOne(newAccount);

        // Return success response with minimal user info (without password)
        return res.status(201).json({
            message: `Driver registered successfully`,
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
 * POST /drivers/login
 * Authenticates driver credentials and returns a JWT token.
 */
app.post('/drivers/login', async (req, res) => {
    try {
        const collection = "drivers";
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required." });
        }

        const existingAcc = await db.collection(collection).findOne({ email: email });
        if (!existingAcc) {
            return res.status(404).json({ error: "Driver not registered." });
        }

        if (!checkStatus(existingAcc, ACCOUNT_STATUS.ACTIVE)) {
            return res.status(403).json({ error: "Account not active" });
        }

        const isMatch = await bcrypt.compare(password, existingAcc.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const token = jwt.sign(
            {
                id: existingAcc._id.toString(),
                role: existingAcc.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        return res.status(200).json({
            message: "Login successful",
            token,
            driver: {
                id: existingAcc._id,
                username: existingAcc.username,
                email: existingAcc.email,
                phone: existingAcc.phone
            }
        });

    } catch (err) {
        console.error("Login Error:", err);
        return res.status(500).json({ error: "Failed to login." });
    }
});

/**
 * GET /drivers/profile/:id
 * Retrieves the profile of the authenticated driver.
 */
app.get('/drivers/profile/:id', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "drivers";
        const driverId = req.params.id;

        if (req.auth.id !== driverId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const driver = await db.collection(collection).findOne(
            { _id: new ObjectId(driverId) },
            { projection: { password: 0 } }
        );

        if (!driver) {
            return res.status(404).json({ error: "Driver not found" });
        }

        const rating = 
            driver.ratingCount === 0
            ? null
            : (driver.ratingSum / driver.ratingCount).toFixed(1);

        return res.status(200).json({
            message: "Driver profile retrieved successfully",
            driver,
            rating
        });

    } catch (err) {
        console.error("View Profile Error:", err);
        return res.status(500).json({ error: "Failed to retrieve profile" });
    }
});

/**
 * PATCH /drivers/profile/:id
 * Update the profile of the authenticated user.
 */
app.patch('/drivers/profile/:id', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "drivers";
        const driverId = req.params.id;

        if (req.auth.id !== driverId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        // Fix the field that allow to update
        const allowedFields = [
            "username",
            "phone",
            "licenseNumber",
            "licenseExpiry",
            "bankAccountNumber"
        ];

        const updateData = {};

        // Filter valid update field from request body
        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updateData[field] = req.body[field];
            }
       }

       // No update process when the updateData is empty
       if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No valid fields provided for update" });
        }

        const result = await db.collection(collection).updateOne(
            { _id: new ObjectId(driverId) },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Driver not found" });
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
 * POST /drivers/vehicle
 * Register vehicle detail.
 */
app.post('/drivers/vehicle', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "vehicles";
        const driverId = new ObjectId(req.auth.id);

        const { plateNumber, vehicleType, brand, model, color, inspectionExpiry, roadtaxExpiry } = req.body;

        if (!plateNumber || !vehicleType || !brand || !model || !color || !inspectionExpiry || !roadtaxExpiry) {
            return res.status(400).json({ error: "Missing information." });
        }

        if (!Object.values(VEHICLE_TYPE).includes(vehicleType)) {
            return res.status(400).json({
                error: "Invalid vehicle type."
            });
        }

        const newVehicle = {
            driverId,
            plateNumber,
            vehicleType,
            brand, 
            model, 
            color, 
            inspectionExpiry, 
            roadtaxExpiry,
            createdAt: new Date(),
            status : VEHICLE_STATUS.ACTIVE
        };

        const result = await db.collection(collection).insertOne(newVehicle);

        return res.status(201).json({
            message: `Vehicle registered successfully`,
            id: result.insertedId,
            plateNumber,
            vehicleType
        });

    } catch (err) {
        console.error("Vehicle Register Error:", err);
        res.status(500).json({ error: "Vehicle registration failed." });
    }
});

/**
 * GET /drivers/vehicle/:id
 * Retrieves the vehicle detail.
 */
app.get('/drivers/vehicle/:id', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "vehicles";
        const vehicleId = req.params.id;
        const driverId = new ObjectId(req.auth.id);

        const vehicle = await db.collection(collection).findOne(
            { 
                _id: new ObjectId(vehicleId),
                driverId : driverId,
                status : VEHICLE_STATUS.ACTIVE
            }
        );

        if (!vehicle) {
            return res.status(404).json({ error: "Vehicle not found or already inactive." });
        }

        return res.status(200).json({
            message: "Vehicle detail retrieved successfully",
            vehicle
        });

    } catch (err) {
        console.error("View Vehicle Error:", err);
        return res.status(500).json({ error: "Failed to retrieve vehicle" });
    }
});

/**
 * PATCH /drivers/vehicle/:id
 * Update the vehicle detail
 */
app.patch('/drivers/vehicle/:id', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "vehicles";
        const vehicleId = req.params.id;
        const driverId = new ObjectId(req.auth.id);

        const allowedFields = [
            "color", 
            "inspectionExpiry", 
            "roadtaxExpiry"
        ];

        const updateData = {};

        // Filter valid update field from request body
        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                updateData[field] = req.body[field];
            }
        };

        // No update process when the updateData is empty
        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No valid fields provided for update" });
        }

        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(vehicleId),
                driverId: driverId,
                status: VEHICLE_STATUS.ACTIVE
            },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Vehicle not found or already inactive." });
        }

        return res.status(200).json({
            message: "Vehicle updated successfully",
            updatedFields: updateData
        });

    } catch (err) {
        console.error("Update Vehicle Error:", err);
        return res.status(500).json({ error: "Failed to update vehicle" });
    }
});

/**
 * PATCH /drivers/vehicle/:id/deactivate
 * Deactive the vehicle with PATCH Request to update status without delete the history of booking
 */
app.patch('/drivers/vehicle/:id/deactivate', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "vehicles";
        const vehicleId = req.params.id;
        const driverId = new ObjectId(req.auth.id);

        const updateData = {
            status : VEHICLE_STATUS.INACTIVE,
            deactivatedAt: new Date()
        }

        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(vehicleId),
                driverId: driverId,
                status: VEHICLE_STATUS.ACTIVE
            },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Vehicle not found or already inactive." });
        }

        return res.status(200).json({
            message: "Vehicle deactivate successfully",
            vehicleId: vehicleId,
            status: VEHICLE_STATUS.INACTIVE
        });
    } catch (err) {
        console.error("Deactivate Vhicle Error:", err);
        return res.status(500).json({ error: "Failed to deactivate vehicle" });
    }
});

// TODO: 2 endpoint to on and off vehicle status

/**
 * GET /drivers/booking
 * Retrieves all available booking.
 */
app.get('/drivers/booking', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "bookings";

        // TODO: Function to extract driver vehicle type to match user request

        const bookings = await db
            .collection(collection)
            .find(
                { status: RIDE_STATUS.REQUESTED }, 
                { projection: { userId: 0 } })
            .toArray();

        if (bookings.length === 0) {
            return res.status(404).json({ error: "No available bookings" });
        }

        return res.status(200).json({
            message: "Bookings retrieved successfully",
            bookings
        });

    } catch (err) {
        console.error("View Bookings Error:", err);
        return res.status(500).json({ error: "Failed to retrieve bookings" });
    }
});

/**
 * PATCH /drivers/booking/:id/accept
 * Driver accepts a booking. Creates a ride record in "rides" collection.
 */
app.patch('/drivers/booking/:id/accept', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const bookingsCollection = "bookings";
        const ridesCollection = "rides";
        const vehiclesCollection = "vehicles";
        const paymentsCollection = "payments";

        const bookingId = new ObjectId(req.params.id);
        const driverId = new ObjectId(req.auth.id);

        // Check available vehicle of driver
        const driverVehicle = await db.collection(vehiclesCollection).findOne({
            driverId: driverId,
            status: VEHICLE_STATUS.ACTIVE
        });

        if (!driverVehicle) {
            return res.status(400).json({ error: "No active vehicle found. Register a vehicle first." });
        }

        // Find the booking detail
        const booking = await db.collection(bookingsCollection).findOne({
            _id: bookingId,
            status: RIDE_STATUS.REQUESTED
        });

        if (!booking) {
            return res.status(404).json({ error: "Booking not found or already accepted/cancelled." });
        }

        // Check whether driver vehicle type match user request 
        if (booking.requestedVehicleType && booking.requestedVehicleType !== driverVehicle.vehicleType) {
            return res.status(400).json({ error: "Your vehicle type does not match the booking request." });
        }

        // Update booking status
        await db.collection(bookingsCollection).updateOne(
            { _id: bookingId },
            { $set: { status: RIDE_STATUS.ACCEPTED } }
        );

        const newRide = {
            bookingId: booking._id,
            userId: booking.userId,
            driverId: driverId,
            vehicleId: driverVehicle._id,
            acceptedAt: new Date(),
            distance: booking.estimatedDistance,
            fare: booking.estimatedFare,
            status: RIDE_STATUS.ACCEPTED
        };

        const rideResult = await db.collection(ridesCollection).insertOne(newRide);

        // **Create initial payment record**
        const paymentData = {
            rideId: rideResult.insertedId,
            userId: booking.userId,
            driverId: driverId,
            amount: booking.estimatedFare,
            status: PAYMENT_STATUS.PENDING,
            createdAt: new Date()
        };

        await db.collection(paymentsCollection).insertOne(paymentData);

        const responseRide = {
            rideId: rideResult.insertedId,
            bookingId: booking._id,
            driverId: driverId,
            vehicleId: driverVehicle._id,
            acceptedAt: newRide.acceptedAt,
            distance: newRide.distance,
            fare: newRide.fare,
            status: newRide.status
        };

        return res.status(200).json({
            message: "Booking accepted successfully",
            ride: responseRide
        });

    } catch (err) {
        console.error("Accept Booking Error:", err);
        return res.status(500).json({ error: "Failed to accept booking." });
    }
});

/**
 * PATCH /drivers/ride/:id/start
 * Driver starts a ride. Updates startedAt and status.
 */
app.patch('/drivers/ride/:id/start', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "rides";
        const rideId = new ObjectId(req.params.id);
        const driverId = new ObjectId(req.auth.id);

        const updateData = {
            status: RIDE_STATUS.ONGOING,
            startedAt: new Date()
        };

        const result = await db.collection(collection).updateOne(
            {
                _id: rideId,
                driverId: driverId,
                status: RIDE_STATUS.ACCEPTED
            },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Ride not found or not in a startable state." });
        }

        return res.status(200).json({
            message: "Ride started successfully",
            rideId: rideId,
            status: updateData.status,
            startedAt: updateData.startedAt
        });
    } catch (err) {
        console.error("Start Ride Error:", err);
        return res.status(500).json({ error: "Failed to start ride" });
    }
});


/**
 * PATCH /drivers/ride/:id/complete
 * Driver completes a ride. Updates completedAt, status, fare, distance, duration.
 */
app.patch('/drivers/ride/:id/complete', authenticate, authorize([ROLES.DRIVER]), async (req, res) => {
    try {
        const collection = "rides";
        const rideId = new ObjectId(req.params.id);
        const driverId = new ObjectId(req.auth.id);

        const ride = await db.collection(collection).findOne({
            _id: rideId,
            driverId,
            status: RIDE_STATUS.ONGOING
        });

        if (!ride) {
            return res.status(404).json({
            error: "Ride not found or not in progress"
            });
        }

        const duration = (new Date() - ride.startedAt) / 60; // In seconds

        const updateData = {
            status: RIDE_STATUS.COMPLETED,
            completedAt: new Date(),
            duration
        };

        const result = await db.collection(collection).updateOne(
            {
                _id: rideId,
                driverId: driverId,
                status: RIDE_STATUS.ONGOING
            },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Ride not found or not in progress." });
        }

        return res.status(200).json({
            message: "Ride completed successfully",
            rideId: rideId,
            status: updateData.status,
            completedAt: updateData.completedAt,
            distance : ride.distance,
            duration,
            fare : ride.fare
        });
    } catch (err) {
        console.error("Complete Ride Error:", err);
        return res.status(500).json({ error: "Failed to complete ride" });
    }
});

// ==========================
// RIDES
// ==========================

/**
 * GET /rides/:id
 * View ride detail.
 * Accessible by both driver and user.
 * Shows enriched info about the other party.
 */
app.get('/rides/:id', authenticate, authorize([ROLES.USER, ROLES.DRIVER]), async (req, res) => {
    try {
        const rideId = new ObjectId(req.params.id);
        const collection = "rides";

        const authId = new ObjectId(req.auth.id);

        // Find ride and enrich info with $lookup
        const ride = await db.collection(collection).aggregate([
            {
                $match: {
                    _id: rideId,
                    
                    // Authorization procedure to ensure only relevent user and driver can access
                    $or: [
                        { userId: authId },
                        { driverId: authId }
                    ]
                }
            },

            // Retrieve user info
            {
                $lookup: {
                    from: "users",
                    localField: "userId",
                    foreignField: "_id",
                    as: "user"
                }
            },
            { $unwind: "$user" },

            // Retrieve driver info
            {
                $lookup: {
                    from: "drivers",
                    localField: "driverId",
                    foreignField: "_id",
                    as: "driver"
                }
            },
            { $unwind: "$driver" },

            // Retrieve driver vehicle detail
            {
                $lookup: {
                    from: "vehicles",
                    localField: "vehicleId",
                    foreignField: "_id",
                    as: "vehicle"
                }
            },
            { $unwind: "$vehicle" },

            // Projection to define which data can display to both user and driver of the rides
            {
                $project: {
                    _id: 1,
                    status: 1,
                    bookingId: 1,
                    acceptedAt: 1,
                    arrivedAt: 1,
                    startedAt: 1,
                    completedAt: 1,
                    distance: 1,
                    duration: 1,
                    fare: 1,

                    user: {
                        username: "$user.username",
                        phone: "$user.phone",
                    },

                    driver: {
                        username: "$driver.username",
                        phone: "$driver.phone",
                        rating: {
                            $cond: [
                                { $eq: ["$driver.ratingCount", 0] },
                                null,
                                { $divide: ["$driver.ratingSum", "$driver.ratingCount"] }
                            ]
                        },
                    },

                    vehicle: {
                        vehicleType: "$vehicle.vehicleType",
                        plateNumber: "$vehicle.plateNumber",
                        brand: "$vehicle.brand",
                        model: "$vehicle.model",
                        color: "$vehicle.color"
                    }
                }
            }
        ]).toArray();

        if (ride.length === 0) {
            return res.status(404).json({ error: "Ride not found or access denied" });
        }

        return res.status(200).json({
            message: "Ride retrieved successfully",
            ride: ride[0]
        });

    } catch (err) {
        console.error("View Ride Error:", err);
        return res.status(500).json({ error: "Failed to retrieve ride" });
    }
});

/**
 * PATCH /rides/:id/cancel
 * Cancel the ride with PATCH Request to update status without delete the history of rides
 */
app.patch('/rides/:id/cancel', authenticate, authorize([ROLES.USER, ROLES.DRIVER]), async (req, res) => {
    try {
        const rideId = new ObjectId(req.params.id);
        const collection = "rides";

        const authId = new ObjectId(req.auth.id);

        const updateData = {
            status : RIDE_STATUS.CANCELLED,
            cancelledAt : new Date()
        }

        const result = await db.collection(collection).updateOne(
            {
                _id: rideId,
                $or: [
                        { userId: authId },
                        { driverId: authId }
                    ],
                status: RIDE_STATUS.ACCEPTED
            },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Ride not found." });
        }

        return res.status(200).json({
            message: "Ride cancelled successfully",
            rideId: rideId,
            status: RIDE_STATUS.CANCELLED
        });
    } catch (err) {
        console.error("Cancel Ride Error:", err);
        return res.status(500).json({ error: "Failed to cancel ride" });
    }
});
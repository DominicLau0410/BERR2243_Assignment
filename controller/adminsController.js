/**
 * adminsController.js
 * Admin related controllers for managing users, drivers, rides,
 * and admin authentication.
 */

// Import module to access mongoDB
const { ObjectId } = require('mongodb');
const { getDB } = require('../db');

// Import modules for password hashing and authentication
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const saltRounds = 10;

// Import module for constants
const { ACCOUNT_STATUS, ROLES, RIDE_STATUS } = require('../utils/constants');

// Import modules for function
const checkStatus = require('../utils/checkStatus');
const rideDetail = require('../utils/rideDetail');


/**
 * Internal admin registration
 */
async function adminRegistration(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "admins";

        // Destructure input from request body
        const { username, email, password } = req.body;

        // Validate required fields
        if (!username || !email || !password ) {
            return res.status(400).json({ error: "Missing information." });
        }

        // Check whether the email already exists in the database
        const existingAcc = await db.collection(collection).findOne({ email: email });
        if (existingAcc) {
            return res.status(409).json({ error: "Account already registered." });
        }

        // Hash the password before storing it to prevent plaintext password leaks
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Prepare new driver object to insert into database
        const newAccount = {
            role : ROLES.ADMIN,
            username,
            email,
            password: hashedPassword,
            createdAt: new Date(),
            status : ACCOUNT_STATUS.ACTIVE
        };

        // Insert new admin document into MongoDB
        const result = await db.collection(collection).insertOne(newAccount);

        // Return success response with minimal admin info (without password)
        return res.status(201).json({
            message: `Admin registered successfully`,
            id: result.insertedId,
            username,
            email
        });

    } catch (err) {
        console.error("Register Error:", err);
        res.status(500).json({ error: "Registration failed." });
    }
};

/**
 * Authenticates admin credentials and returns a JWT token.
 */
async function adminLogin(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "admins";

        // Destructure input from request body
        const { email, password } = req.body;
        
        // Validate required fields
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required." });
        }

        // Check whether the email exists in the database
        const existingAcc = await db.collection(collection).findOne({ email: email });
        if (!existingAcc) {
            return res.status(404).json({ error: "Admin not registered." });
        }

        // Check account status
        if (!checkStatus(existingAcc, ACCOUNT_STATUS.ACTIVE)) {
            return res.status(403).json({ error: "Account not active" });
        }

        // Compare the hashing password
        const isMatch = await bcrypt.compare(password, existingAcc.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        // Generate token to authenticate and authorize process
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
            admin: {
                id: existingAcc._id,
                username: existingAcc.username,
                email: existingAcc.email
            }
        });

    } catch (err) {
        console.error("Login Error:", err);
        return res.status(500).json({ error: "Failed to login." });
    }
};

/**
 * Retrieve all users
 */
async function getUser(req, res) {
    try {
        // Access to mongoDB 
        const db = getDB();

        // Define collection
        const collection = "users";

        // Retrieve all user in database
        const users = await db.collection(collection).find(
            {}, 
            { projection: { _id: 1, username: 1, phone: 1, email: 1, status: 1 } }
        ).toArray();

        return res.status(200).json({
            message: "Users retrieved successfully",
            users
        });

    } catch (err) {
        console.error("Get Users Error:", err);
        return res.status(500).json({ error: "Failed to retrieve users" });
    }
};

/**
 * Retrieve a single user by ID
 */
async function getUserById(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";

        // Define user id
        const userId = req.params.id;

        // Retrieve user in database
        const userDetails = await db.collection(collection).aggregate([
            { $match: { _id: new ObjectId(userId) } },
            {
                // Retrieve user info in bookings collection
                $lookup: {
                from: "bookings",
                localField: "_id",
                foreignField: "userId",
                as: "bookings"
                }
            },
            {
                // Retrieve user info in rides collection
                $lookup: {
                from: "rides",
                localField: "_id",
                foreignField: "userId",
                as: "rides"
                }
            },
            {
                // Retrieve user info in payments collection
                $lookup: {
                from: "payments",
                localField: "_id",
                foreignField: "userId",
                as: "payments"
                }
            },
            {
                // Retrieve user info in ratings collection
                $lookup: {
                from: "ratings",
                localField: "_id",
                foreignField: "userId",
                as: "ratings"
                }
            },
            { $project: { password: 0 } } //Ignore password for security
            ]).toArray();

        // Check whether the user exists in the database
        if (!userDetails || userDetails.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
            message: "User retrieved successfully",
            user: userDetails[0]
        });

    } catch (err) {
        console.error("Get User Error:", err);
        return res.status(500).json({ error: "Failed to retrieve user" });
    }
};

/**
 * Update user details, including password
 */
async function updateUser(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";

        // Define user id
        const userId = req.params.id;

        // Fix the field that allow to update
        const allowedFields = [
            "username",
            "phone",
            "preferPay",
            "bankAccountNumber",
            "password"
        ];

        const updateData = {};

        // Filter valid update field from request body
        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                if (field === "password") {
                    updateData.password = await bcrypt.hash(req.body.password, saltRounds);
                } else {
                    updateData[field] = req.body[field];
                }
            }
        }

        // No update process when the updateData is empty
        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No valid fields provided for update" });
        }

        // Update data in database
        const result = await db.collection(collection).updateOne(
            { _id: new ObjectId(userId) },
            { $set: updateData }
        );

        // Check whether the user exists in the database
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
            message: "User updated successfully",
            updatedFields: Object.keys(updateData).filter(f => f !== "password") // Ignore password for security
        });

    } catch (err) {
        console.error("Update User Error:", err);
        return res.status(500).json({ error: "Failed to update user" });
    }
};

/**
 * Suspend user account without deleting
 */
async function suspendUser(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";

        // Define user id
        const userId = req.params.id;

        // Define update status 
        const updateData = {
            status: ACCOUNT_STATUS.SUSPENDED, 
            suspendedAt: new Date()
        };

        // Update status in database
        const result = await db.collection(collection).updateOne(
            { 
                _id: new ObjectId(userId), 
                status: ACCOUNT_STATUS.ACTIVE 
            },
            { $set: updateData }
        );

        // Check whether the user exists in the database
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Not found or already inactive" });
        }

        return res.status(200).json({
            message: "User suspended successfully",
            userId,
            status: ACCOUNT_STATUS.SUSPENDED
        });

    } catch (err) {
        console.error("Deactivate User Error:", err);
        return res.status(500).json({ error: "Failed to suspend user" });
    }
};

/**
 * Reactivate user account
 */
async function activateUser(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";

        // Define user id
        const userId = req.params.id;

        // Define update status
        const updateData = {
            status: ACCOUNT_STATUS.ACTIVE,
            suspendedAt: null
        };

        // Update status in database
        const result = await db.collection(collection).updateOne(
            { 
                _id: new ObjectId(userId), 
                $or: [
                    { status: ACCOUNT_STATUS.SUSPENDED },
                    { status: ACCOUNT_STATUS.INACTIVE }
                ] // Allow to active suspend or inactive account
            },
            { $set: updateData }
        );

        // Check whether the user exists in the database
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Not found or already active" });
        }

        return res.status(200).json({
            message: "User reactivated successfully",
            userId,
            status: ACCOUNT_STATUS.ACTIVE
        });

    } catch (err) {
        console.error("Activate User Error:", err);
        return res.status(500).json({ error: "Failed to reactivate user" });
    }
};

/**
 * Retrieve all drivers
 */
async function getDriver(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Retrieve all driver in database
        const drivers = await db.collection(collection).find(
            {}, 
            { projection: { _id: 1, username: 1, phone: 1, email: 1, status: 1 } }
        ).toArray();

        return res.status(200).json({
            message: "Drivers retrieved successfully",
            drivers
        });

    } catch (err) {
        console.error("Get Drivers Error:", err);
        return res.status(500).json({ error: "Failed to retrieve drivers" });
    }
};

/**
 * GET /admins/driver/:id
 * Retrieve a single user by ID
 */
async function getDriverById(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Define driver id
        const driverId = req.params.id;

        // Retrieve driver in database
        const driverDetails = await db.collection(collection).aggregate([
            { $match: { _id: new ObjectId(driverId) } },
            {
                // Retrieve driver info in vehicles collection
                $lookup: {
                from: "vehicles",
                localField: "_id",
                foreignField: "driverId",
                as: "vehicles"
                }
            },
            {
                // Retrieve driver info in rides collection
                $lookup: {
                from: "rides",
                localField: "_id",
                foreignField: "driverId",
                as: "rides"
                }
            },
            {
                // Retrieve driver info in payments collection
                $lookup: {
                from: "payments",
                localField: "_id",
                foreignField: "driverId",
                as: "payments"
                }
            },
            {
                // Retrieve driver info in ratings collection
                $lookup: {
                from: "ratings",
                localField: "_id",
                foreignField: "driverId",
                as: "ratings"
                }
            },
            { $project: { password: 0 } } //Ignore password for security
            ]).toArray();

        if (!driverDetails || driverDetails.length === 0) {
            return res.status(404).json({ error: "Driver not found" });
        }

        return res.status(200).json({
            message: "Driver retrieved successfully",
            driver: driverDetails[0]
        });

    } catch (err) {
        console.error("Get Driver Error:", err);
        return res.status(500).json({ error: "Failed to retrieve driver" });
    }
};

/**
 * Update driver details, including password
 */
async function updateDriver(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Define driver id
        const driverId = req.params.id;

        // Fix the field that allow to update
        const allowedFields = [
            "username",
            "phone",
            "licenseNumber",
            "licenseExpiry",
            "bankAccountNumber",
            "password"
        ];

        const updateData = {};

        // Filter valid update field from request body
        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                if (field === "password") {
                    updateData.password = await bcrypt.hash(req.body.password, saltRounds);
                } else {
                    updateData[field] = req.body[field];
                }
            }
        }

        // No update process when the updateData is empty
        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No valid fields provided for update" });
        }

        // Update data in database
        const result = await db.collection(collection).updateOne(
            { _id: new ObjectId(driverId) },
            { $set: updateData }
        );

        // Check whether the driver exists in the database
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Driver not found" });
        }

        return res.status(200).json({
            message: "Driver updated successfully",
            updatedFields: Object.keys(updateData).filter(f => f !== "password") // Ignore password for security
        });

    } catch (err) {
        console.error("Update Driver Error:", err);
        return res.status(500).json({ error: "Failed to update driver" });
    }
};

/**
 * Deactivate driver account without deleting
 */
async function suspendDriver(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Define driver id
        const driverId = req.params.id;

        // Define update status
        const updateData = {
            status: ACCOUNT_STATUS.SUSPENDED, 
            suspendedAt: new Date()
        };

        // Update status in database
        const result = await db.collection(collection).updateOne(
            { 
                _id: new ObjectId(driverId), 
                status: ACCOUNT_STATUS.ACTIVE 
            },
            { $set: updateData }
        );

        // Check whether the driver exists in the database
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Not found or already inactive" });
        }

        return res.status(200).json({
            message: "Driver deactivated successfully",
            driverId,
            status: ACCOUNT_STATUS.SUSPENDED
        });

    } catch (err) {
        console.error("Deactivate Driver Error:", err);
        return res.status(500).json({ error: "Failed to deactivate driver" });
    }
};

/**
 * Reactivate driver account
 */
async function activateDriver(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Define driver id
        const driverId = req.params.id;

        // Define update status
        const updateData = {
            status: ACCOUNT_STATUS.ACTIVE,
            suspendedAt: null
        };

        // Update status in database
        const result = await db.collection(collection).updateOne(
            { 
                _id: new ObjectId(driverId), 
                $or: [
                    { status: ACCOUNT_STATUS.SUSPENDED },
                    { status: ACCOUNT_STATUS.INACTIVE }
                ] // Allow to active suspend or inactive account
            },
            { $set: updateData }
        );

        // Check whether the driver exists in the database
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Not found or already active" });
        }

        return res.status(200).json({
            message: "Driver reactivated successfully",
            driverId,
            status: ACCOUNT_STATUS.ACTIVE
        });

    } catch (err) {
        console.error("Activate Driver Error:", err);
        return res.status(500).json({ error: "Failed to reactivate driver" });
    }
};

/**
 * Retrieve all ride
 */
async function getRide(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "rides";

        // Retrieve all ride in database
        const rides = await db.collection(collection).find(
            {}, 
            { projection: { _id: 1, userId: 1, driverId: 1, vehicleId: 1, distance: 1, duration: 1, fare: 1, status: 1 } }
        ).toArray();

        return res.status(200).json({
            message: "Rides retrieved successfully",
            rides
        });

    } catch (err) {
        console.error("Get Rides Error:", err);
        return res.status(500).json({ error: "Failed to retrieve rides" });
    }
};

/**
 * Retrieve ride detail (admin)
 */
async function getRideById(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define ride id
        const rideId = req.params.id;

        // Retrieve ride in database
        const ride = await rideDetail({
            rideId: new ObjectId(rideId),
            isAdmin: true
        });

        // Check whether the driver exists in the database
        if (!ride || ride.length === 0) {
            return res.status(404).json({
                error: "Ride not found or access denied"
            });
        }

        return res.status(200).json({
            message: "Ride retrieved successfully",
            ride
        });

    } catch (err) {
        console.error("View Ride Error:", err);
        return res.status(500).json({
            error: "Failed to retrieve ride"
        });
    }
};

/**
 * Admin force cancel a ride
 */
async function forceCancelRide(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "rides";

        // Define ride id
        const rideId = req.params.id;

        // Cancel the ride
        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(rideId),
                status: { $in: [RIDE_STATUS.ACCEPTED, RIDE_STATUS.ONGOING] }
            },
            {
                $set: {
                    status: RIDE_STATUS.CANCELLED,
                    cancelledAt: new Date(),
                    cancelledBy: "ADMIN"
                }
            }
        );

        // Check whether the ride exists in the database
        if (result.matchedCount === 0) {
            return res.status(404).json({
                error: "Ride not found or cannot be cancelled"
            });
        }

        return res.status(200).json({
            message: "Ride cancelled by admin",
            rideId
        });

    } catch (err) {
        console.error("Admin Cancel Ride Error:", err);
        return res.status(500).json({ error: "Failed to cancel ride" });
    }
};

//Export the admins controller function
module.exports = { 
    adminRegistration,
    adminLogin,
    getUser,
    getUserById,
    updateUser,
    suspendUser,
    activateUser,
    getDriver,
    getDriverById,
    updateDriver,
    suspendDriver,
    activateDriver,
    getRide,
    getRideById,
    forceCancelRide
};
/**
 * usersController.js
 * User related request handlers.
 */

// Import module to access mongoDB
const { ObjectId } = require('mongodb');
const { getDB } = require('../db');

// Import modules for password hashing and authentication
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const saltRounds = 10;

// Import module for constants
const { ACCOUNT_STATUS, ROLES, PAYMENT_METHOD, VEHICLE_TYPE, RIDE_STATUS, PAYMENT_STATUS } = require('../utils/constants');

// Import modules for function
const checkStatus = require('../utils/checkStatus');

/**
 * Registers a new user and stores a hashed password in the database.
 */
async function userRegistration(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";

        // Destructure user input from request body
        const { username, phone, email, password, preferPay, bankAccountNumber } = req.body;

        // Validate required fields
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
};

/**
 * Authenticates user credentials and returns a JWT token.
 */
async function userLogin(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";
        
        // Destructure user input from request body
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

        // Check the existing account status whether active or deactive
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
};

/**
 * Retrieves the profile of the authenticated user.
 */
async function getProfile(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";
        
        // Define user id
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

        // Check whether the user exists in the database
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
};

/**
 * Update the profile of the authenticated user.
 */
async function updateProfile(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";
        
        // Define user id
        const userId = req.params.id;

        // Ensure the authenticated user can only access their own profile
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

        // Check the validity of payment method if provided
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
            message: "Profile updated successfully",
            updatedFields: updateData
        });

    } catch (err) {
        console.error("Update Profile Error:", err);
        return res.status(500).json({ error: "Failed to update profile" });
    }
};

/**
 * Deactivate own user account
 */
async function deactivateProfile(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "users";
        
        // Define user id
        const userId = req.params.id;
        
        // Ensure the authenticated user can only access their own profile
        if (req.auth.id !== userId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        // Define update status
        const updateData = {
            status : ACCOUNT_STATUS.INACTIVE,
            deactivatedAt : new Date()
        }

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
            return res.status(404).json({ error: "User not found." });
        }

        return res.status(200).json({
            message: "User deactivate successfully",
            userId: userId,
            status: ACCOUNT_STATUS.INACTIVE
        });
    } catch (err) {
        console.error("Deactivate User Error:", err);
        return res.status(500).json({ error: "Failed to deactivate account" });
    }
};

/**
 * Create new booking.
 */
async function createBooking(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "bookings";
        
        // Destructure user input from request body
        const { pickupLocation, dropoffLocation, requestedVehicleType } = req.body;
        
        const userId = new ObjectId(req.auth.id); // Save the id in ObjectId form
        const estimatedDistance = 10; // Temporary fixed distance (10 km).
        const estimatedFare = 4.1 + (estimatedDistance * 2);

        // Validate required fields
        if (!pickupLocation || !dropoffLocation || !requestedVehicleType) {
            return res.status(400).json({ error: "Missing information." });
        }

        // Check the validity of vehicle type
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
};

/**
 * View booking detail (user only).
 */
async function getBooking(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "bookings";
       
        // Define booking id
        const bookingId = req.params.id;

        // Define user id
        const userId = req.auth.id;
        
        // Retrieve booking information in database
        const booking = await db.collection(collection).findOne({
            _id: new ObjectId(bookingId),
            userId: new ObjectId(userId)
        });

        // Check whether the booking exists in the database
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
};

/**
 * Update the booking detail
 */
async function updateBooking(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "bookings";
        
        // Define booking id
        const bookingId = req.params.id;

        // Define user id
        const userId = req.auth.id;

        // Fix the field that allow to update
        const allowedFields = [
            "pickupLocation",
            "dropoffLocation",
            "requestedVehicleType"
        ];

        const updateData = {};

        // Check the validity of vehicle type if provided
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

        // Update data in database
        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(bookingId),
                userId: new ObjectId(userId),
                status: RIDE_STATUS.REQUESTED
            },
            { $set: updateData }
        );

        // Check whether the booking exists in the database
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
};

/**
 * Cancel the booking with PATCH Request to update status without delete the history of booking
 */
async function cancelBooking(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "bookings";
        
        // Define booking id
        const bookingId = req.params.id;

        // Define user id
        const userId = req.auth.id;

        // Define update status
        const updateData = {
            status : RIDE_STATUS.CANCELLED,
            cancelledAt : new Date()
        }

        // Update status in database
        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(bookingId),
                userId: new ObjectId(userId),
                status: RIDE_STATUS.REQUESTED
            },
            { $set: updateData }
        );

        // Check whether the booking exists in the database
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
};

/**
 * User pay after ride completed.
 */
async function makePayment(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "payments";
        
        // Define ride id
        const rideId = req.params.id;

        // Define user id
        const userId = req.auth.id;

        // Destructure user input from request body
        const { paymentMethod, transactionReferences } = req.body;

        // Validate required fields
        if (!paymentMethod || !transactionReferences) {
            return res.status(400).json({ error: "Missing information." });
        }

        // Check the validity of payment method
        if (!Object.values(PAYMENT_METHOD).includes(paymentMethod)) {
            return res.status(400).json({
                error: "Invalid payment method."
            });
        }

        // Define update data
        const updateData = {
            paymentMethod,
            transactionReferences,
            status : PAYMENT_STATUS.SUCCESS,
            paidAt : new Date()
        }

        // Update data in database
        const result = await db.collection(collection).updateOne(
            {
                rideId: new ObjectId(rideId),
                userId: new ObjectId(userId),
                status: PAYMENT_STATUS.PENDING
            },
            { $set: updateData }
        );

        // Check whether the payment exists in the database
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
};

/**
 * User rates a completed ride.
 */
async function rateRide(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();
        const ridesCollection = "rides";
        const ratingsCollection = "ratings";
        const driversCollection = "drivers";

        // Define ride id
        const rideId = req.params.id;

        // Define user id
        const userId = req.auth.id;

        // Destructure user input from request body
        const { rating, comment } = req.body;

        if (!Number.isInteger(rating) || rating < 1 || rating > 5 ) {
            return res.status(400).json({
                error: "Rating must be an integer between 1 and 5."
            });
        }

        // Find the completed ride
        const ride = await db.collection(ridesCollection).findOne({
            _id: new ObjectId(rideId),
            userId: new ObjectId(userId),
            status: RIDE_STATUS.COMPLETED
        });

        // Check whether the ride exists in the database
        if (!ride) {
            return res.status(404).json({
                error: "Ride not found, not completed, or access denied."
            });
        }

        // Check if rating already exists
        const existingRating = await db.collection(ratingsCollection).findOne({
            rideId: new ObjectId(rideId),
            userId: new ObjectId(userId)
        });

        // Check whether the rating detail already rated or not
        if (existingRating) {
            return res.status(400).json({ error: "This ride has already been rated." });
        }

        // Insert new rating
        await db.collection(ratingsCollection).insertOne({
            rideId: new ObjectId(rideId),
            userId: new ObjectId(userId),
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
};

// Export the users controller functions
module.exports = {
    userRegistration,
    userLogin,
    getProfile,
    updateProfile,
    deactivateProfile,
    createBooking,
    getBooking,
    updateBooking,
    cancelBooking,
    makePayment,
    rateRide
};
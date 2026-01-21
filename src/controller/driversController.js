/**
 * driversController.js
 * Driver related request handlers.
 */

// Import module to access mongoDB
const { ObjectId } = require('mongodb');
const { getDB } = require('../db');

// Import modules for password hashing and authentication
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const saltRounds = 10;

// Import module for constants
const { ACCOUNT_STATUS, ROLES, RIDE_STATUS, VEHICLE_STATUS, VEHICLE_TYPE, PAYMENT_STATUS } = require('../utils/constants');

// Import modules for function
const checkStatus = require('../utils/checkStatus');

/**
 * Registers a new driver and stores a hashed password in the database.
 */
async function driverRegistration(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Destructure input from request body
        const { username, phone, email, password, licenseNumber, licenseExpiry, bankAccountNumber } = req.body;

        // Validate required fields
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
        
        // Prepare new driver object to insert into database
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

        // Return success response with minimal driver info (without password)
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
};

/**
 * Authenticates driver credentials and returns a JWT token.
 */
async function driverLogin(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Destructure input from request body
        const { email, password } = req.body;
        
        // Validate required fields
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required." });
        }

        // Check whether the email exists in the database
        const existingAcc = await db.collection(collection).findOne({ email: email });
        if (!existingAcc) {
            return res.status(404).json({ error: "Driver not registered." });
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
};

/**
 * Retrieves the profile of the authenticated driver.
 */
async function getProfile(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Define driver id
        const driverId = req.params.id;

        // Ensure the authenticated driver can only access their own profile
        if (req.auth.id !== driverId) {
            return res.status(403).json({ error: "Forbidden" });
        }

        // Retrieve driver profile information in database
        const driver = await db.collection(collection).findOne(
            { _id: new ObjectId(driverId) },
            { projection: { password: 0 } }
        );

        // Check whether the driver exists in the database
        if (!driver) {
            return res.status(404).json({ error: "Driver not found" });
        }

        // Calculation for driver rating
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
};

/**
 * Update the profile of the authenticated driver.
 */
async function updateProfile(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "drivers";

        // Define driver id
        const driverId = req.params.id;

        // Ensure the authenticated driver can only access their own profile
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
        const collection = "drivers";

        // Define driver id
        const driverId = req.params.id;
        
        // Ensure the authenticated driver can only access their own profile
        if (req.auth.id !== driverId) {
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
                _id: new ObjectId(driverId),
                status: ACCOUNT_STATUS.ACTIVE
            },
            { $set: updateData }
        );

        // Check whether the driver exists in the database
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Driver not found." });
        }

        return res.status(200).json({
            message: "Driver deactivate successfully",
            driverId: driverId,
            status: ACCOUNT_STATUS.INACTIVE
        });
    } catch (err) {
        console.error("Deactivate Driver Error:", err);
        return res.status(500).json({ error: "Failed to deactivate account" });
    }
};

/**
 * Register vehicle detail.
 */
async function newVehicle(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "vehicles";

        // Define driver id
        const driverId = req.auth.id;

        // Destructure input from request body
        const { plateNumber, vehicleType, brand, model, color, inspectionExpiry, roadtaxExpiry } = req.body;

        // Validate required fields
        if (!plateNumber || !vehicleType || !brand || !model || !color || !inspectionExpiry || !roadtaxExpiry) {
            return res.status(400).json({ error: "Missing information." });
        }

        // Check the validity of vehicle type
        if (!Object.values(VEHICLE_TYPE).includes(vehicleType)) {
            return res.status(400).json({
                error: "Invalid vehicle type."
            });
        }

        // Prepare new vehicle object to insert into database
        const newVehicle = {
            driverId: new ObjectId(driverId),
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

        // Insert new vehicle document into MongoDB
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
};

/**
 * Retrieves the vehicle detail.
 */
async function getVehicle(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "vehicles";

        // Define vehicle id
        const vehicleId = req.params.id;

        // Define driver id
        const driverId = req.auth.id;

        // Retrieve vehicle information in database
        const vehicle = await db.collection(collection).findOne(
            { 
                _id: new ObjectId(vehicleId),
                driverId : new ObjectId(driverId),
                status : VEHICLE_STATUS.ACTIVE
            }
        );

        // Check whether the vehicle exists in the database
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
};

/**
 * Update the vehicle detail
 */
async function updateVehicle(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "vehicles";

        // Define vehicle id
        const vehicleId = req.params.id;

        // Define driver id
        const driverId = req.auth.id;

        // Fix the field that allow to update
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

        // Update data in database
        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(vehicleId),
                driverId: new ObjectId(driverId),
                status: VEHICLE_STATUS.ACTIVE
            },
            { $set: updateData }
        );

        // Check whether the vehicle exists in the database
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
};

/**
 * Deactive the vehicle with PATCH Request to update status without delete the history of booking
 */
async function deactivateVehicle(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "vehicles";

        // Define vehicle id
        const vehicleId = req.params.id;

        // Define driver id
        const driverId = req.auth.id;

        // Define update status 
        const updateData = {
            status : VEHICLE_STATUS.INACTIVE,
            deactivatedAt: new Date()
        }

        // Update status in database
        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(vehicleId),
                driverId: new ObjectId(driverId),
                status: VEHICLE_STATUS.ACTIVE
            },
            { $set: updateData }
        );

        // Check whether the vehicle exists in the database
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
};

/**
 * Retrieves all available booking.
 */
async function getBooking(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "bookings";

        // Find all available booking
        const bookings = await db.collection(collection).find(
                { status: RIDE_STATUS.REQUESTED }, 
                { projection: { userId: 0 } }
        ).toArray();

        // Check the available booking
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
};

/**
 * Driver accepts a booking. Creates a ride record in "rides" collection.
 */
async function acceptBooking(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collections
        const bookingsCollection = "bookings";
        const ridesCollection = "rides";
        const vehiclesCollection = "vehicles";
        const paymentsCollection = "payments";

        // Define booking id
        const bookingId = req.params.id;

        // Define driver id
        const driverId = req.auth.id;

        // Check available vehicle of driver
        const driverVehicle = await db.collection(vehiclesCollection).findOne({
            driverId: new ObjectId(driverId),
            status: VEHICLE_STATUS.ACTIVE
        });

        // Check whether the vehicle exists in the database
        if (!driverVehicle) {
            return res.status(400).json({ error: "No active vehicle found. Register a vehicle first." });
        }

        // Find the booking detail
        const booking = await db.collection(bookingsCollection).findOne({
            _id: new ObjectId(bookingId),
            status: RIDE_STATUS.REQUESTED
        });

        // Check whether the booking exists in the database
        if (!booking) {
            return res.status(404).json({ error: "Booking not found or already accepted/cancelled." });
        }

        // Check whether driver vehicle type match user request 
        if (booking.requestedVehicleType && booking.requestedVehicleType !== driverVehicle.vehicleType) {
            return res.status(400).json({ error: "Your vehicle type does not match the booking request." });
        }

        // Update status in database
        await db.collection(bookingsCollection).updateOne(
            { _id: new ObjectId(bookingId) },
            { $set: { status: RIDE_STATUS.ACCEPTED } }
        );

        // Prepare new ride object to insert into database
        const newRide = {
            bookingId: booking._id,
            userId: booking.userId,
            driverId: new ObjectId(driverId),
            vehicleId: driverVehicle._id,
            acceptedAt: new Date(),
            distance: booking.estimatedDistance,
            fare: booking.estimatedFare,
            status: RIDE_STATUS.ACCEPTED
        };

        // Insert new ride document into MongoDB
        const rideResult = await db.collection(ridesCollection).insertOne(newRide);

        // Prepare new payment information of the ride to insert into database
        const paymentData = {
            rideId: rideResult.insertedId,
            userId: booking.userId,
            driverId: new ObjectId(driverId),
            amount: booking.estimatedFare,
            status: PAYMENT_STATUS.PENDING,
            createdAt: new Date()
        };

        // Insert new payment document into MongoDB
        await db.collection(paymentsCollection).insertOne(paymentData);

        // Prepare response object
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
};

/**
 * Driver starts a ride. Updates startedAt and status.
 */
async function startRide(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "rides";

        // Define ride id
        const rideId = req.params.id;

        // Define driver id
        const driverId = req.auth.id;

        // Define update status 
        const updateData = {
            status: RIDE_STATUS.ONGOING,
            startedAt: new Date()
        };

        // Update status in database
        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(rideId),
                driverId: new ObjectId(driverId),
                status: RIDE_STATUS.ACCEPTED
            },
            { $set: updateData }
        );

        // Check whether the ride exists in the database
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
};


/**
 * Driver completes a ride. Updates completedAt, status, fare, distance, duration.
 */
async function completeRide(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define collection
        const collection = "rides";

        // Define ride id
        const rideId = req.params.id;

        // Define driver id
        const driverId = req.auth.id;

        // Find the ride information
        const ride = await db.collection(collection).findOne({
            _id: new ObjectId(rideId),
            driverId: new ObjectId(driverId),
            status: RIDE_STATUS.ONGOING
        });

        // Check whether the ride exists in the database
        if (!ride) {
            return res.status(404).json({
            error: "Ride not found or not in progress"
            });
        }

        const duration = Math.floor((Date.now() - ride.startedAt) / 1000); // In seconds

        // Define update status 
        const updateData = {
            status: RIDE_STATUS.COMPLETED,
            completedAt: new Date(),
            duration
        };

        // Update status in database
        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(rideId),
                driverId: new ObjectId(driverId),
                status: RIDE_STATUS.ONGOING
            },
            { $set: updateData }
        );

        // Check whether the ride exists in the database
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
};

//Export the drivers controller function
module.exports = { 
    driverRegistration,
    driverLogin,
    getProfile,
    updateProfile,
    deactivateProfile,
    newVehicle,
    getVehicle,
    updateVehicle,
    deactivateVehicle,
    getBooking,
    acceptBooking,
    startRide,
    completeRide
};
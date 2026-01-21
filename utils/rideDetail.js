/**
 * ride.service.js
 * Shared ride logic (aggregation for rideDetail)
 */

// Import modules to access mongoDB
const { ObjectId } = require('mongodb');
const { getDB } = require('../db');

/**
 * Retrieves the ride detail
 */
async function rideDetail( {rideId, authId, isAdmin = false}) {
    // Access to mongoDB
    const db = getDB();
    
    // To ensure admin can directly access the ride detail
    // However only the relevent user and driver can access
    const matchStage = isAdmin
        ? { _id: new ObjectId(rideId) }
        : {
            _id: new ObjectId(rideId),
            $or: [
                { userId: new ObjectId(authId) },
                { driverId: new ObjectId(authId) }
            ]
        };
    
    const ride = await db.collection("rides").aggregate([
            { $match: matchStage },

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

    return ride[0] || null;
}

// Export function
module.exports = rideDetail;
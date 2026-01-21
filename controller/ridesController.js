/**
 * ridesController.js
 * Ride-related request handlers.
 * Handles ride detail retrieval and ride cancellation.
 */

// Import module to access mongoDB
const { ObjectId } = require('mongodb');
const { getDB } = require('../db');

// Import module for constants
const { RIDE_STATUS } = require('../utils/constants');

// Import modules for function
const rideDetail = require('../utils/rideDetail');

/**
 * View ride detail.
 * Accessible by both driver and user.
 * Shows enriched info about the other party.
 */
async function getRideDetail(req, res) {
    try {
        // Access to mongoDB
        const db = getDB();

        // Define ride Id
        const rideId = req.params.id;

        // Define auth Id
        const authId = req.auth.id;

        // Retrieve ride detail
        const ride = await rideDetail({
            rideId: new ObjectId(rideId), 
            authId: new ObjectId(authId),
            isAdmin : false
        });

        // Check whether the ride exists in the database
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
 * Cancel the ride with PATCH Request to update status without delete the history of rides
 */
async function cancelRide(req, res) {
    try {
        // Access to mongoDB
        const db = getDB()

        // Define collection
        const collection = "rides";

        // Define ride Id
        const rideId = req.params.id;

        // Define auth Id
        const authId = req.auth.id;

        // Define update status
        const updateData = {
            status : RIDE_STATUS.CANCELLED,
            cancelledAt : new Date()
        }

        // Update status in database
        const result = await db.collection(collection).updateOne(
            {
                _id: new ObjectId(rideId),
                $or: [
                        { userId: new ObjectId(authId) },
                        { driverId: new ObjectId(authId) }
                    ], // Only relevent user and driver can access
                status: RIDE_STATUS.ACCEPTED // The ride only able to cancel before the ride start
            },
            { $set: updateData }
        );

        // Check whether the ride exists in the database
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
};

//Export the rides controller function
module.exports = {
    getRideDetail,
    cancelRide
};
/**
 * authenticate.js
 * Middleware to verify JWT token and attach user info to req
 */

// Import module for authentication
const jwt = require('jsonwebtoken');

// Import module to access mongoDB
const { ObjectId } = require('mongodb');
const { getDB } = require('../db');

// Import module for constants
const { ACCOUNT_STATUS, ROLES } = require('../utils/constants');

// Import module for function
const checkStatus = require('../utils/checkStatus');

/**
 * Middleware to verify JWT token from the Authorization header.
 * If valid, attaches decoded payload to req.auth.id
 * Returns 401 Unauthorized if token is missing or invalid.
 */
async function authenticate(req, res, next) {
    try {
        // Get token from "Authorization: Bearer <token>"
        const authHeader = req.headers.authorization;

        // Check whether token header start from "Bearer"
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Missing or invalid Authorization header' });
        }
        
        const token = authHeader.split(' ')[1];
        
        // Verify JWT and decode payload
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log(decoded.id);
        console.log(decoded.role);
        
        // Define collection according to role 
        let collection;
        switch (decoded.role) {
            case ROLES.ADMIN:
                collection = "admins";
                break;
            case ROLES.DRIVER:
                collection = "drivers";
                break;
            default:
                collection = "users"
        }

        // Access to mongoDB to view data
        const db = getDB();
        const account = await db.collection(collection).findOne({ _id: new ObjectId(decoded.id) });
        
        // Check if account exist
        if (!account) {
            return res.status(401).json({ error: 'Account not found' });
        }

        // Check if account is active
        if (!checkStatus(account, ACCOUNT_STATUS.ACTIVE)) {
            return res.status(403).json({ error: 'Account not active' });
        }
        
        req.auth = {
            id: decoded.id,
            role: decoded.role
        };

        next();
    } catch {
        return res.status(401).json({ error: "Invalid token" });
    }
}

module.exports = authenticate;
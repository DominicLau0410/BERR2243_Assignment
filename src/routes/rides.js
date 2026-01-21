/**
 * rides.js
 * Ride-related routes.
 */

// Import module for express and express initialize
const express = require('express');
const router = express.Router();

// Import modules for authenticate and authorize
const authenticate = require('../middlewares/authenticate');
const authorize = require('../middlewares/authorize');

// Import module for constants
const { ROLES } = require('../utils/constants');

// Import the controller of admins
const ridesController = require('../controller/ridesController');

/**
 * GET /:id
 * View ride detail.
 * Accessible by both driver and user.
 * Shows enriched info about the other party.
 */
router.get('/:id', authenticate, authorize([ROLES.USER, ROLES.DRIVER]), ridesController.getRideDetail);

/**
 * PATCH /:id/cancel
 * Cancel the ride with PATCH Request to update status without delete the history of rides
 */
router.patch('/:id/cancel', authenticate, authorize([ROLES.USER, ROLES.DRIVER]), ridesController.cancelRide);

module.exports = router;
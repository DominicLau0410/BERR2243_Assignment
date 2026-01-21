/**
 * drivers.js
 * Driver related routes.
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
const driversController = require('../controller/driversController');

/**
 * POST /register
 * Registers a new driver
 */
router.post('/register', driversController.driverRegistration);

/**
 * POST /login
 * Driver login
 */
router.post('/login', driversController.driverLogin);

/**
 * GET /profile/:id
 * Retrieve own profile
 */
router.get('/profile/:id', authenticate, authorize([ROLES.DRIVER]), driversController.getProfile);

/**
 * PATCH /profile/:id
 * Update own profile
 */
router.patch('/profile/:id', authenticate, authorize([ROLES.DRIVER]), driversController.updateProfile);

/**
 * PATCH /profile/:id/deactivate
 * Deactivate own account
 */
router.patch('/profile/:id/deactivate', authenticate, authorize([ROLES.DRIVER]), driversController.deactivateProfile);

/**
 * POST /vehicle
 * Register a new vehicle
 */
router.post('/vehicle', authenticate, authorize([ROLES.DRIVER]), driversController.newVehicle);

/**
 * GET /vehicle/:id
 * Retrieve vehicle detail
 */
router.get('/vehicle/:id', authenticate, authorize([ROLES.DRIVER]), driversController.getVehicle);

/**
 * PATCH /vehicle/:id
 * Update vehicle detail
 */
router.patch('/vehicle/:id', authenticate, authorize([ROLES.DRIVER]), driversController.updateVehicle);

/**
 * PATCH /vehicle/:id/deactivate
 * Deactivate vehicle
 */
router.patch('/vehicle/:id/deactivate', authenticate, authorize([ROLES.DRIVER]), driversController.deactivateVehicle);

/**
 * GET /booking
 * Retrieve all available bookings
 */
router.get('/booking', authenticate, authorize([ROLES.DRIVER]), driversController.getBooking);

/**
 * PATCH /booking/:id/accept
 * Accept a booking
 */
router.patch('/booking/:id/accept', authenticate, authorize([ROLES.DRIVER]), driversController.acceptBooking);

/**
 * PATCH /ride/:id/start
 * Start a ride
 */
router.patch('/ride/:id/start', authenticate, authorize([ROLES.DRIVER]), driversController.startRide);

/**
 * PATCH /ride/:id/complete
 * Complete a ride
 */
router.patch('/ride/:id/complete', authenticate, authorize([ROLES.DRIVER]), driversController.completeRide);

module.exports = router;
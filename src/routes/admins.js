/**
 * admins.js
 * Admin routes for user, driver, and ride management.
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
const adminsController = require('../controller/adminsController');

/**
 * POST /register
 * Internal admin registration
 */
router.post('/register', adminsController.adminRegistration);


/**
 * POST /login
 * Authenticates admin credentials and returns a JWT token.
 */
router.post('/login', adminsController.adminLogin);

/**
 * GET /user
 * Retrieve all users
 */
router.get('/user', authenticate, authorize([ROLES.ADMIN]), adminsController.getUser);

/**
 * GET /user/:id
 * Retrieve a single user by ID
 */
router.get('/user/:id', authenticate, authorize([ROLES.ADMIN]), adminsController.getUserById);

/**
 * PATCH /user/:id
 * Update user details, including password
 */
router.patch('/user/:id', authenticate, authorize([ROLES.ADMIN]), adminsController.updateUser);

/**
 * PATCH /user/:id/suspend
 * Deactivate user account without deleting
 */
router.patch('/user/:id/suspend', authenticate, authorize([ROLES.ADMIN]), adminsController.suspendUser);

/**
 * PATCH /user/:id/activate
 * Reactivate user account
 */
router.patch('/user/:id/activate', authenticate, authorize([ROLES.ADMIN]), adminsController.activateUser);

/**
 * GET /driver
 * Retrieve all drivers
 */
router.get('/driver', authenticate, authorize([ROLES.ADMIN]), adminsController.getDriver);

/**
 * GET /driver/:id
 * Retrieve a single user by ID
 */
router.get('/driver/:id', authenticate, authorize([ROLES.ADMIN]), adminsController.getDriverById);

/**
 * PATCH /driver/:id
 * Update driver details, including password
 */
router.patch('/driver/:id', authenticate, authorize([ROLES.ADMIN]), adminsController.updateDriver);

/**
 * PATCH /driver/:id/suspend
 * Deactivate driver account without deleting
 */
router.patch('/driver/:id', authenticate, authorize([ROLES.ADMIN]), adminsController.suspendDriver);

/**
 * PATCH /driver/:id/activate
 * Reactivate driver account
 */
router.patch('/driver/:id', authenticate, authorize([ROLES.ADMIN]), adminsController.activateDriver);

/**
 * GET /ride
 * Retrieve all ride
 */
router.get('/ride', authenticate, authorize([ROLES.ADMIN]), adminsController.getRide);

/**
 * GET /ride/:id
 * Retrieve ride detail (admin)
 */
router.get('/ride/:id', authenticate, authorize([ROLES.ADMIN]), adminsController.getRideById);

/**
 * PATCH /ride/:id/cancel
 * Admin force cancel a ride
 */
router.patch('/ride/:id/cancel', authenticate, authorize([ROLES.ADMIN]), adminsController.forceCancelRide);

module.exports = router;
/**
 * users.js
 * User related routes.
 */

// Import module for express and express initialize
const express = require('express');
const router = express.Router();

// Import modules for authenticate and authorize
const authenticate = require('../middlewares/authenticate');
const authorize = require('../middlewares/authorize');

// Import module for constants
const { ROLES } = require('../utils/constants');

// Import the controller of users
const usersController = require('../controller/usersController');

/**
 * POST /register
 * Registers a new user
 */
router.post('/register', usersController.userRegistration);

/**
 * POST /login
 * User login
 */
router.post('/login', usersController.userLogin);

/**
 * GET /profile/:id
 * Retrieve own profile
 */
router.get('/profile/:id', authenticate, authorize([ROLES.USER]), usersController.getProfile);

/**
 * PATCH /profile/:id
 * Update own profile
 */
router.patch('/profile/:id', authenticate, authorize([ROLES.USER]), usersController.updateProfile);

/**
 * PATCH /profile/:id/deactivate
 * Deactivate own account
 */
router.patch('/profile/:id/deactivate', authenticate, authorize([ROLES.USER]), usersController.deactivateProfile);

/**
 * POST /booking
 * Create a new booking
 */
router.post('/booking', authenticate, authorize([ROLES.USER]), usersController.createBooking);

/**
 * GET /booking/:id
 * Retrieve booking detail
 */
router.get('/booking/:id', authenticate, authorize([ROLES.USER]), usersController.getBooking);

/**
 * PATCH /booking/:id
 * Update booking detail
 */
router.patch('/booking/:id', authenticate, authorize([ROLES.USER]), usersController.updateBooking);

/**
 * PATCH /booking/:id/cancel
 * Cancel a booking
 */
router.patch('/booking/:id/cancel', authenticate, authorize([ROLES.USER]), usersController.cancelBooking);

/**
 * PATCH /ride/:id/payment
 * Make a payment for a ride
 */
router.patch('/ride/:id/payment', authenticate, authorize([ROLES.USER]), usersController.makePayment);

/**
 * POST /ride/:id/rating
 * Rate a completed ride
 */
router.post('/ride/:id/rating', authenticate, authorize([ROLES.USER]), usersController.rateRide);

module.exports = router;
/**
 * checkStatus.js
 * Function to check account status
 */

// Import module for constants
const { ACCOUNT_STATUS } = require('./constants');

/**
 * Check if a entity is active
 * Return true if active, false otherwise
 */
function checkStatus(account, requiredStatus = ACCOUNT_STATUS.ACTIVE) {
    if (!account || !account.status) return false;
    return account.status === requiredStatus;
}

// Export function
module.exports = checkStatus;
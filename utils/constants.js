// Account status selection
const ACCOUNT_STATUS = {
    ACTIVE: "active",
    INACTIVE: "inactive",
    SUSPENDED: "suspended"
};

// Payment method selection
const PAYMENT_METHOD = {
    CASH: "cash",
    BANK: "bank",
    CREDIT_CARD: "credit_card"
};

// Payment status selection
const PAYMENT_STATUS = {
    PENDING: "pending",
    SUCCESS: "success"
};

// Ride status selection
const RIDE_STATUS = {
    REQUESTED: "requested",
    ACCEPTED: "accepted",
    ONGOING: "on going",
    COMPLETED: "completed",
    CANCELLED: "cancelled"
};

// Available role selection
const ROLES = {
    USER: "user",
    DRIVER: "driver",
    ADMIN: "admin"
};

// Vehicle status selection
const VEHICLE_STATUS = {
    ACTIVE: "active",
    INACTIVE: "inactive",
};

// Vehicle type selection
const VEHICLE_TYPE = {
    CAR_4P: "4 people car",
    CAR_6P: "6 people car",
    MOTOR: "motor",
    VAN: "van"
};

// Export the selection to allow these selection in other modules
module.exports = {
    ACCOUNT_STATUS,
    PAYMENT_METHOD,
    PAYMENT_STATUS,
    RIDE_STATUS,
    ROLES,
    VEHICLE_STATUS,
    VEHICLE_TYPE
};

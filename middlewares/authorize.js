/**
 * authorize.js
 * Middleware factory for role-based authorization.
 * Returns 403 Forbidden if the user's role is not in the allowed list.
 */
function authorize(allowedRoles = []) {
    // the parameter must be array
    if (!Array.isArray(allowedRoles)) {
        throw new Error('allowedRoles must be an array');
    }
    
    return (req, res, next) => {
        if (!req.auth || !allowedRoles.includes(req.auth.role)) {
            return res.status(403).json({ error: 'Forbidden: insufficient permissions' });
        }
        next();
    };
};

module.exports = authorize;
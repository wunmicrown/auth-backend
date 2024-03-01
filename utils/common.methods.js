/**
 * Exclude specified fields from the original data object.
 * @param {Object} data Original data object
 * @param {Array} fields Array of fields to be omitted from the original data
 * @returns {Object} Modified data object with specified fields omitted
 */
const excludeFields = (data, fields) => {
    // Create a copy of the original data object to avoid mutating it
    const newData = { ...data };
    for (const field of fields) {
        delete newData[field];
    }
    return newData;
};


module.exports = { 
    excludeFields 
};
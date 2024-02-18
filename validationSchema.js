const Joi = require("joi");



const registerPayLoad = Joi.object({
    // The payload object for create user
    firstName: Joi.string()
        .alphanum()
        .min(3)
        .max(40)
        .required(),
    lastName: Joi.string()
        .alphanum()
        .min(3)
        .max(40)
        .required(),
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{8,}$')),
    email: Joi.string().email().required(),

})

// The payload object for user login
const siginPayLoad = Joi.object({
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{8,}$')),
    email: Joi.string().email().required(),

})
// The payload object for reset email
const resetEmailPayLoad = Joi.object({
    email: Joi.string().email().required(),

})

// The payload object for verify Otp
const verifyOTPPayLoad = Joi.object({
    OTP: Joi.string().required(),
})

// The payload object for resend Otp
const resendOTPPayLoad = Joi.object({
    OTP: Joi.string().required(),
})
const uploadFilePayLoad = Joi.object({
    file: Joi.string().required(),
})
const resetPasswordlPayLoad = Joi.object({
    email: Joi.string().email().required(),
})


module.exports = {
    registerPayLoad,
    siginPayLoad,
    resetEmailPayLoad,
    verifyOTPPayLoad,
    resendOTPPayLoad,
    uploadFilePayLoad,
    resetPasswordlPayLoad
};

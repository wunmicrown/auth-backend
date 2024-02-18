const Joi = require("joi");



 const registerPayLoad=Joi.object({
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
    email:Joi.string().email().required(),            

})

// The payload object for create user login
 const loginPayLoad=Joi.object({
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{8,}$')),
    email:Joi.string().email().required(),            

})
 const resetEmailPayLoad=Joi.object({
    email:Joi.string().email().required(),            

})


module.exports={registerPayLoad, loginPayLoad, resetEmailPayLoad};

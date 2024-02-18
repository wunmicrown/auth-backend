const Joi = require("joi");



 const registerPayLoad=Joi.object({
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
    email:Joi.string().email(),            

})


module.exports={registerPayLoad};

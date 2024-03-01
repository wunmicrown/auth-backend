const express = require("express");
const authRoutes = express.Router();

const {
    displayWelcome,
    login,
    signup,
    uploadFile,
    resetpassword,
    resendOTP,
    verifyOTP,
    verifyToken,
    verifyEmail,
    resendSignupOTP,
} = require("../controllers/user.controller");
const { ValidatorMDW } = require("../validators/AuthHandler");
const { TOKEN_MIDDLEWARE } = require("../middlewares/auth.token");

// routes Define

authRoutes.get("/", displayWelcome);
authRoutes.post("/signup", ValidatorMDW, signup);
authRoutes.post("/verifyEmail", verifyEmail);
authRoutes.post("/resendSignupOTP", resendSignupOTP); 
authRoutes.post("/signin", ValidatorMDW, login);
authRoutes.post("/verifyOTP", verifyOTP);
authRoutes.post("/resendOTP", resendOTP);
authRoutes.post("/uploadFile", uploadFile);
authRoutes.post('/resetpassword',  resetpassword);


authRoutes.get('/verifyToken', verifyToken);







module.exports = authRoutes;

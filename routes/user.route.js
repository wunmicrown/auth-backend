const express = require("express");
const router = express.Router();

const {
    displayWelcome,
    login,
    signup,
    uploadFile,
    resetEmail,
    resetpassword,
    resendOTP,
    verifyOTP,
    verifyToken,
    signupVerification,
    resendSignupOTP // Corrected the function name here
} = require("../controllers/user.controller"); // Make sure `resendSignupOTP` is exported from user.controller.js
const { ValidatorMDW } = require("../validators/AuthHandler");

// Define routes
router.get("/", displayWelcome);
router.post("/signup", ValidatorMDW, signup);
router.post("/signupVerify", signupVerification);
router.post("/resendSignupOTP", resendSignupOTP); // Corrected the route path here
router.post("/signin", ValidatorMDW, login);
router.post("/verifyOTP", verifyOTP);
router.post("/resendOTP", resendOTP);
router.post("/uploadFile", uploadFile);
router.post("/resetEmail", ValidatorMDW, resetEmail);
router.post('/resetpassword', ValidatorMDW, resetpassword);
router.post('/verifyToken', verifyToken);

module.exports = router;

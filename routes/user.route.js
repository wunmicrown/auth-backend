const express = require("express");
const router = express.Router();
const authRoutes = express.Router();

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
    resendSignupOTP 
} = require("../controllers/user.controller");
const { ValidatorMDW } = require("../validators/AuthHandler");

// routes Define

router.get("/", displayWelcome);
router.post("/signup", ValidatorMDW, signup);
router.post("/signupVerify", signupVerification);
router.post("/resendSignupOTP", resendSignupOTP); 
router.post("/signin", ValidatorMDW, login);
router.post("/verifyOTP", verifyOTP);
router.post("/resendOTP", resendOTP);
router.post("/uploadFile", uploadFile);
router.post("/resetEmail", ValidatorMDW, resetEmail);
router.post('/resetpassword', ValidatorMDW, resetpassword);
router.post('/verifyToken', verifyToken);

authRoutes.use("/auth", router)


module.exports = authRoutes;

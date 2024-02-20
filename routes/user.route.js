const express = require("express")
const router = express.Router();

const { displayWelcome, login, register, uploadFile, resetEmail, resetpassword, resendOTP, verifyOTP, verifyToken } = require("../controllers/user.controller");
const { ValidatorMDW } = require("../validators/AuthHandler");





router.get("/", displayWelcome);
router.post("/signup", ValidatorMDW, register);
router.post("/signin", ValidatorMDW, login);
router.post("/verifyOTP", verifyOTP);
router.post("/resendOTP", resendOTP);
router.post("/uploadFile", uploadFile);
router.post("/resetEmail", ValidatorMDW, resetEmail);
router.post('/resetpassword', ValidatorMDW, resetpassword);
router.post('/verifyToken',verifyToken )



module.exports = router;
const express = require ("express")
const router = express.Router();

const {displayWelcome, login, register,verifyOTP,resendOTP,uploadFile, resetEmail, resetpassword} = require("../controllers/user.controller")





router.get("/", displayWelcome);
router.post("/register", register);
router.post("/login", login);
router.post("/verifyOTP", verifyOTP);
router.post("/resendOTP", resendOTP);
router.post("/uploadFile", uploadFile);
router.post("/resetEmail", resetEmail)
router.post('/resetpassword', resetpassword)



module.exports = router;
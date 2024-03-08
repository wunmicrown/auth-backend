const express = require("express");
const authRoutes = express.Router();

const {
    displayWelcome,
    login,
    signup,
    resetpassword,
    resendOTP,
    verifyOTP,
    verifyToken,
    verifyEmail,
    resendEmailOTP,
    verifyChangedEmail,
    changePassword,
    testUpload,
    update_user
} = require("../controllers/user.controller");
const { ValidatorMDW } = require("../validators/AuthHandler");
const { TOKEN_MIDDLEWARE } = require("../middlewares/auth.token");
const { multerUploader, multerDynamicUploader, multerCloudUploader } = require("../middlewares/multer.upload");

// routes Define

authRoutes.get("/", displayWelcome);
authRoutes.post("/signup", ValidatorMDW, signup);
authRoutes.post("/verifyEmail",  TOKEN_MIDDLEWARE, verifyEmail);
authRoutes.post("/verifyChangedEmail", verifyChangedEmail);
authRoutes.post("/resendEmailOTP", resendEmailOTP); 
authRoutes.post("/signin", ValidatorMDW, login);
authRoutes.post("/verifyOTP", verifyOTP);
authRoutes.post("/resendOTP", resendOTP);
authRoutes.post('/resetpassword',  resetpassword);
authRoutes.post('/changePassword',  changePassword);
authRoutes.post("/updateUser", TOKEN_MIDDLEWARE,update_user)


authRoutes.get('/verifyToken', verifyToken);

// authRoutes.post("/upload-dp",TOKEN_MIDDLEWARE, multerUploader.single("image"), testUpload) // Single file
// authRoutes.post("/upload-dp", TOKEN_MIDDLEWARE, multerUploader.array("image" /*, 4*/), testUpload) // Multiple file


authRoutes.post("/upload-dp",TOKEN_MIDDLEWARE, multerCloudUploader.single("image"), testUpload) // Single file
// authRoutes.post("/upload-dp", TOKEN_MIDDLEWARE, multerCloudUploader.array("image" /*, 4*/), testUpload) // Multiple file

// authRoutes.post("/upload-dp", multerDynamicUploader("videos/").single("image"), testUpload) // Dynamic path Single file
// authRoutes.post("/upload-dp", multerDynamicUploader("images/").array("image" /*, 4*/), testUpload) // Dynamic path Multiple file











module.exports = authRoutes;

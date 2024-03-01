const apiRoutes = require("express").Router();

const {
    verifyToken,
    getUserDetails,
    resetEmail
} = require("../controllers/user.controller");
const { ValidatorMDW } = require("../validators/AuthHandler");

apiRoutes.post("/resetEmail", ValidatorMDW, resetEmail);
apiRoutes.post('/verifyToken', verifyToken);
apiRoutes.get('/getUser',  getUserDetails);

module.exports = apiRoutes;

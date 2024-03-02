const apiRoutes = require("express").Router();

const {
    verifyToken,
    getUserDetails,
    resetEmail
} = require("../controllers/user.controller");
const { TOKEN_MIDDLEWARE } = require("../middlewares/auth.token");
// const { ValidatorMDW } = require("../validators/AuthHandler");

// apiRoutes.post("/resetEmail", TOKEN_MIDDLEWARE, resetEmail);
apiRoutes.post("/resetEmail",  resetEmail);
apiRoutes.post('/verifyToken', verifyToken);
apiRoutes.get('/getUser',  getUserDetails);

module.exports = apiRoutes;

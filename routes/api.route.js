const apiRoutes = require("express").Router();

const {
    verifyToken,
    getUserDetails,
    resetEmail,
    changeEmail,
} = require("../controllers/user.controller");
const { TOKEN_MIDDLEWARE } = require("../middlewares/auth.token");
// const { ValidatorMDW } = require("../validators/AuthHandler");

apiRoutes.post("/resetEmail", TOKEN_MIDDLEWARE, resetEmail);
apiRoutes.post("/changeEmail", TOKEN_MIDDLEWARE, changeEmail);
// apiRoutes.post("/resetEmail",  resetEmail);
apiRoutes.post('/verifyToken', verifyToken);
apiRoutes.get('/getUser',  getUserDetails);

module.exports = apiRoutes;

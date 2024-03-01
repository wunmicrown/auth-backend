const { TOKEN_MIDDLEWARE } = require("../middlewares/auth.token");
const apiRoutes = require("./api.route");
const authRoutes = require("./auth.route");

const routers = require("express").Router();

routers.use("/auth", authRoutes)
routers.use("/api", TOKEN_MIDDLEWARE, apiRoutes)


module.exports = routers;
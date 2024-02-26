const express = require("express")
const app = express()
const router = express.Router()
const cors = require("cors")
require("dotenv").config()
let PORT = process.env.PORT
const userRouter = require("./routes/user.route")


app.use(cors())
app.use(express.urlencoded({ extended: true, limit: "50mb" }))
app.use(express.json({ limit: "50mb" }))
router.get("/", (req, res) => {
    return res.status(200).send("App is live");
})

app.use("/", router)
app.use("/api", userRouter)




app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT} `);
});
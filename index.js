const express = require("express")
const app = express()
const cors = require("cors")
require("dotenv").config()
let PORT = process.env.PORT
const userRouter = require("./routes/user.route")


app.use(cors())
app.use(express.urlencoded({ extended: true,limit: "50mb"}))
app.use(express.json({limit: "50mb"}))
app.use("/", userRouter)




app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT} `);
});
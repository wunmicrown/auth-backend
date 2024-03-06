"use strict"
const express = require("express")
const app = express()
const router = express.Router()
const cors = require("cors")
const routers = require("./routes/all.route")
require("dotenv").config()
let PORT = process.env.PORT


app.use(cors())
app.use(express.urlencoded({ extended: true, limit: "50mb" }))
app.use(express.json({ limit: "50mb" }))
app.use("/uploads", express.static("uploads"))

router.get("/", (req, res) => {
    return res.status(200).send("App is live");
})

app.use("/", router)
app.use("/v1",routers)




app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT} `);
});
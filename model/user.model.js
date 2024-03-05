const mongoose = require('mongoose');
const bcrypt = require("bcrypt")
const env = require("dotenv");
// const validationSchema=require("../validationSchema")
let URI = process.env.URI
mongoose.connect(URI)
    .then((response) => {
        console.log("connected to database successfully");
    })
    .catch((err) => {
        console.log(err);
        console.log("There is an error in the database");
    })

    let studentSchema = mongoose.Schema({
        firstName: String,
        lastName: String,
        otp: { type: Number, unique: true },
        emailVerified: { type: Boolean, default: false },
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        profilePic: String,
        bio: String,
        oldPassword: String, // Add oldPassword field
        newPassword: String, // Add newPassword field
        confirmPassword: String, // Add confirmPassword field
    });
    

studentSchema.pre("save", function (next) {
    bcrypt.hash(this.password, 10, (err, hash) => {
        console.log(hash);
        this.password = hash;
        next();
    })
})

let Student = mongoose.model("Student", studentSchema)

module.exports = Student
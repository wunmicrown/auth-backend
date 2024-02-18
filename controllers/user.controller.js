const Student = require("../model/user.model");
const bcrypt = require('bcrypt');
const cloudinary = require("cloudinary");
require('dotenv').config();
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const { signupPayloadValidator, schemaValidatorHandler, resetEmailPayLoad, resetPasswordlPayLoad } = require("../validators/AuthSchema");
const from = process.env.MAIL_USER


const displayWelcome = (req, res) => {
  res.send("Hello World");
  console.log("Hello World");
};


cloudinary.config({
  cloud_name: 'dphfgjzit',
  api_key: '879477868729251',
  api_secret: process.env.API_SECRET
});

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  }
});

const  generateFourDigitNumber=()=> {
  return Math.floor(Math.random() * 9000) + 1000;
}

const register = async (req, res) => {
  console.log(req.body, req.url, req.route);
  try {
    // Check if the user already exists
    const { email } = req.body;
    const userExists = await Student.findOne({ email });
    if (userExists) {
      return res.status(409).send("User already exists");
    }

    let student = new Student(req.body);
    const user = await student.save(); 
    console.log("User registered successfully");
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal server error");
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const student = await Student.findOne({ email });
    if (!student) {
      console.log("User not found");
      res.status(404).send("User not found");
      return;
    }
    const match = await bcrypt.compare(password, student.password);
    if (!match) {
      console.log("Invalid password");
      res.status(401).send("Invalid password");
      return;
    }
    console.log("Login successful");
    res.status(200).send("Login successful");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
};

const sendOTP = async (email) => {
  try {
    const otp = otpGenerator.generate(4, { upperCase: false, specialChars: false, alphabets: false });
    console.log(`OTP sent to ${email}: ${otp}`);
    await Student.updateOne({ email: email }, { $set: { otp: otp } });
    return otp;
  } catch (error) {
    console.log("Error sending OTP:", error);
    throw error;
  }
};

const verifyOTP = async (req, res) => {
  const { email, otpCodes } = req.body;
  console.log(email, otpCodes);
  try {
    const user = await Student.findOne({ email: email });
    if (!user) {
      console.log("User not found");  
      res.status(404).send("User not found");
      return;
    }
    if (user.OTP == otpCodes) {
      console.log("OTP verified successfully");
      res.status(200).send("OTP verified successfully");
    } else {
      console.log("Invalid OTP");
      res.status(400).send("Invalid OTP");
    }
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).send("Internal server error");
  }
};

// Controller function to resend OTP
const resendOTP = async (req, res) => {
  const { email } = req.body;
  try {
    const otp = await sendOTP(email);
    // res.status(200).send("OTP resent successfully");
    res.status(200).json({ message: "OTP resent successfully", status: true });
  } catch (error) {
    console.error("Error resending OTP:", error);
    res.status(500).send("Internal server error");
  }
};
const uploadFile = (req, res) => {
  let image = req.body.myFile;
  cloudinary.uploader.upload(image, ((result, err) => {
    console.log(result);
    let storedImage = result.secure_url;
    res.send({ message: "image uploaded  successfully", status: true, storedImage });
  }))
}

const resetEmail = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await Student.findOne({ email });
    if (user) {
      const OTP = generateFourDigitNumber();
      const mailOptions = {
        from: from,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is: ${OTP}`
      };
      const mailResponse = await transporter.sendMail(mailOptions);
      console.log('Email sent:', mailResponse);

      const updateResponse = await Student.findOneAndUpdate({ email }, { OTP });
      if (updateResponse) {
        res.status(200).json({ message: 'OTP sent and user updated successfully', status: true });
      } else {
        res.status(500).json({ message: 'Failed to update user', status: false });
      }
    } else {
      res.status(404).json({ message: 'User does not exist', status: false });
    }
  } catch (err) {
    console.error('Error sending OTP:', err);
    res.status(500).json({ message: 'Oops! Something went wrong', status: false });
  }
};


const resetpassword = async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10); // 10 is the number of salt rounds

    // Update the user's password in the database
    const user = await Student.findOneAndUpdate({ email }, { password: hashedPassword });

    if (user) {
      // Password updated successfully
      res.status(200).json({ message: 'Password reset successful', status: true });
    } else {
      // User not found
      res.status(500).json({ message: 'User not found', status: false });
    }
  } catch (error) {
    // Error occurred
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Internal server error', status: false });
  }
};


module.exports = {
  displayWelcome,
  register,
  login,
  verifyOTP,
  resendOTP,
  uploadFile,
  resetEmail,
  resetpassword
};

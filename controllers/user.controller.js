const Student = require("../model/user.model");
const bcrypt = require('bcrypt');
const cloudinary = require("cloudinary");
require('dotenv').config();
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const {
  signupPayloadValidator,
  schemaValidatorHandler,
  resetEmailPayLoad,
  resetPasswordlPayLoad

} = require("../validators/AuthSchema");
const from = process.env.MAIL_USER
const jwt = require("jsonwebtoken")

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

const generateFourDigitNumber = () => {
  return Math.floor(Math.random() * 9000) + 1000;
}

const generateSixDigitNumber = () => {
  return Math.floor(Math.random() * 900000) + 100000;
};


const signup = async (req, res) => {
  console.log(req.body, req.url, req.route);
  try {
    // Check if the user already exists
    const { email } = req.body;
    const userExists = await Student.findOne({ email });
    if (userExists) {
      return res.status(409).send("User already exists");
    }

    // Hash the password before saving the user
    if (req.body.password) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10); 
      req.body.password = hashedPassword;
    }

    // Generate an OTP for email verification
    const otpGen = generateSixDigitNumber();

    // Save the OTP to the database
    const student = new Student({
      ...req.body,
      otp: otpGen // Save OTP along with other user details
    });
    const user = await student.save();

    // Send OTP to the user's email
    const mailOptions = {
      from: process.env.MAIL_USER,
      to: email,
      subject: 'Verify Your Email',
      text: `Your OTP for email verification is: ${otpGen}`,
      // Optionally, include an HTML version
      html: `<p>Your OTP for email verification is: <strong>${otpGen}</strong></p>`,
    };

    transporter.sendMail(mailOptions, function(error, info){
      if (error) {
        console.log(error);
        res.status(500).send("Failed to send verification email");
      } else {
        console.log('Email sent: ' + info.response);
        res.status(201).send({ message: "User registered successfully. Verification OTP sent to email.", user: user });
      }
    });
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal server error");
  }
};





const signupVerification = async (req, res) => {
    const { otp } = req.body;
   Student.findOne({ otp })
   .then((user)=>{
    
      if(user.otp == otp){
        console.log("OTP verified");
        res.send({message:"OTP verifed successfully", status: true})
      }else{
        console.log("OTP not verified")
      }
   })
    
}

 
  



const resendSignupOTP = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await Student.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate a new OTP
    const otp = generateSixDigitNumber();
    // Update the user's OTP in the database
    user.otp = otp;
    await user.save();

    // Send the new OTP to the user's email
    const mailOptions = {
      from: process.env.MAIL_USER,
      to: email,
      subject: 'Resend OTP',
      text: `Your new OTP is: ${otp}`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: 'New OTP sent successfully' });
  } catch (error) {
    console.error('Error resending OTP:', error);
    res.status(500).json({ message: 'Failed to resend OTP' });
  }
};


const login = (req, res) => {
  const { email, password } = req.body;

  Student.findOne({ email })
    .then(user => {
      if (!user) {
        console.log("User not found");
        return res.status(404).json({ message: "User not found" });
      }

      // Compare the provided password with the hashed password in the database
      bcrypt.compare(password, user.password)
        .then(match => {
          if (!match) {
            console.log("Incorrect password");
            return res.status(401).json({ message: "Incorrect password" });
          }

          // Password is correct, proceed with login
          const token = jwt.sign({ email }, process.env.SECRETKEY, { expiresIn: '1h' });
          return res.status(200).json({ message: "Login successful", status: true, user, token });
        })
        .catch(error => {
          console.error("Error comparing passwords:", error);
          return res.status(500).json({ message: "Internal server error" });
        });
    })
    .catch(error => {
      console.error("Error finding user:", error);
      return res.status(500).json({ message: "Internal server error" });
    });
};





const verifyToken = (req, res) => {
  const { token } = req.body;
  const secretkey = process.env.SECRETKEY;


  if (!token) {
    return res.status(401).send({ message: 'Token not provided', status: false });
  }


  jwt.verify(token, secretkey, (err, decoded) => {
    console.log(decoded);
    if (err) {
      console.error('Token Verification failed:', err.message)
      return res.status(401).json({ message: 'Token verification failed', status: false });
    } else {
      console.log('Token verified successfully');
      res.status(200).send({ message: 'Token verified successfully', status: true, token: token, valid: true });
    }
  });
}

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
  signup,
  login,
  verifyOTP,
  resendOTP,
  uploadFile,
  resetEmail,
  resetpassword,
  verifyToken,
  signupVerification,
  resendSignupOTP
};


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
const jwt = require("jsonwebtoken");
const { excludeFields } = require("../utils/common.methods");

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

// global varibale for genarating OTP
const generateSixDigitNumber = () => {
  return Math.floor(Math.random() * 900000) + 100000;
};



/**
 * Registers a new user by saving their details (including OTP) to the database and sending a verification email.
 * 
 * @param {Object} req - The request object containing user details in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the registration process is complete.
 */
const signup = async (req, res) => {
  // console.log(req.body, req.url, req.route);
  try {
    // Destructure email from the request body
    const { email } = req.body;

    // Check if the user already exists
    const userExists = await Student.findOne({ email });
    if (userExists) {
      return res.status(409).send("User already exists");
    }

    // Hash the password before saving the user
    if (req.body.password) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      req.body.password = hashedPassword;
      console.log(hashedPassword);
    }

    // Generate an OTP for email verification
    const otpGen = generateSixDigitNumber();

    // Saving the OTP to the database
    const student = new Student({
      ...req.body,
      otp: otpGen // Save OTP along with other user details
    });
    let user = await student.save();
    user = excludeFields(user.toObject(), ['password', 'otp', "__v"]);
    // console.log(_user);
    // Sending OTP to the user's email
    const mailOptions = {
      from: process.env.MAIL_USER,
      to: email,
      subject: 'Verify Your Email',
      text: `Your OTP for email verification is: ${otpGen}`,
      // Optionally, include an HTML version
      html: `<p>Your OTP for email verification is: <strong>${otpGen}</strong></p>`,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
        res.status(500).send("Failed to send verification email");
      } else {
        console.log('Email sent: ' + info.response);
        res.status(201).send({ message: "User registered successfully. Verification OTP sent to email.", user: user });
      }
    });
  } catch (err) {
    console.error("Error during signup:", err);
    res.status(500).send("Internal server error");
  }
};


/**
 * Verifies the OTP sent during the signup process.
 * 
 * @param {Object} req - The request object containing the OTP in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the OTP verification process is complete.
 */


// Backend code to handle OTP verification

const verifyEmail = async (req, res) => {
  const { email, otp } = req.body;
console.log({email,otp});
  try {
    // Find the user by email
    let user = await Student.findOne({ email, otp });
    if(!user){
      return res.status(400).json({ message: "Invalid OTP" });
    }
    // If OTP is correct, mark email as verified
    user.emailVerified = true;
    user = await user.save();
    user = excludeFields(user.toObject(), ["password", "otp"])
    return res.status(200).json({message:"Email successfully verified", user});
  } catch (error) {
    console.error("Error verifying email:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};



/**
 * Resends a new OTP to the user's email for signup verification.
 * 
 * @param {Object} req - The request object containing the user's email in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the OTP resend process is complete.
 */
const resendSignupOTP = async (req, res) => {
  // Destructure email from the request body
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await Student.findOne({ email });

    // Check if user exists
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



/**
 * Logs in a user by verifying their email and password.
 * 
 * @param {Object} req - The request object containing user's email and password in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the login process is complete.
 */
const login = async (req, res) => {
  // Destructure email and password from the request body
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await Student.findOne({ email });
    const _user = excludeFields(user.toObject(), ['password', 'otp', "__v"]);
    // console.log(_user);
    // Check if user exists
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ message: "Invalid credentials", status: false });
    }
    // Log the plaintext password and the hashed password retrieved from the database
    // console.log("Plaintext password:", password, user.password);
    // console.log("Hashed password from database:", user.password);


    // Compare the provided password with the hashed password in the database
    const match = await bcrypt.compare(password, user.password);
    console.log(match);
    console.log("bcrypt.compare result:", match);
    // Check if passwords match
    if (!match) {
      console.log("Incorrect password");
      return res.status(401).send({ message: "Invalid credentials", status: false });
    }

    // Password is correct, generate JWT token for authentication
    const token = jwt.sign({ email }, process.env.SECRETKEY, { expiresIn: '1h' });
    // Send successful login response with user details and token
    return res.status(200).json({ message: "Login successful", status: true, user:_user, token });
  } catch (error) {
    console.error("Error during login:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};



/**
 * Verifies the authenticity of a token sent in the request.
 * 
 * @param {Object} req - The request object containing the token in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the token verification process is complete.
 */
const verifyToken = (req, res) => {
  // Extract the token from the request headers    
  const { authorization } = req.headers;
  // Check if token is provided
  if (!authorization) {
    return res.status(401).send({ message: 'Unauthorized request, please login', status: false });
  }

  /**
   * Auhtorization header expected in form of "Bearer token"
   */
  // Get the secret key for token verification
  const token = authorization.split(' ')[1];
  if (!authorization) {
    return res.status(401).send({ message: 'Unauthorized request, please login', status: false });
  }

  const secretkey = process.env.SECRETKEY;

  // Verify the token using the secret key
  jwt.verify(token, secretkey, async (err, decoded) => {
    // Check if token verification failed
    if (err) {
      console.error('Token Verification failed:', err.message);
      return res.status(401).send({ message: 'Unauthorized request, please login', status: false });
    } else {
      return res.status(200).send({ message: 'Token Verified', status: true, expiresIn: decoded.exp });
    }
  });
};


/**
 * Generates and sends an OTP (One-Time Password) to the provided email address.
 * Saves the OTP to the corresponding user document in the database.
 * 
 * @param {string} email - The email address to which the OTP will be sent.
 * @returns {Promise<string>} - A promise that resolves to the generated OTP.
 * @throws {Error} - Throws an error if there's an issue generating or sending the OTP.
 */
const sendOTP = async (email) => {
  try {
    // Generate a new OTP
    const otp = otpGenerator.generate(4, { upperCase: false, specialChars: false, alphabets: false });

    // Log OTP information
    console.log(`OTP sent to ${email}: ${otp}`);

    // Update the user document in the database with the new OTP
    await Student.updateOne({ email: email }, { $set: { otp: otp } });

    // Return the generated OTP
    return otp;
  } catch (error) {
    // Handle errors
    console.log("Error sending OTP:", error);
    throw error;
  }
};



/**
 * Controller function to resend OTP (One-Time Password) to the user's email address.
 * 
 * @param {Object} req - The request object containing the user's email in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the OTP resend process is complete.
 */
const resendOTP = async (req, res) => {
  const { email } = req.body;
  try {
    // Generate a new OTP
    const otp = generateSixDigitNumber(); // Assuming generateSixDigitNumber is a function that generates a new OTP as a number

    // Sending OTP to the user's email
    const mailOptions = {
      from: process.env.MAIL_USER,
      to: email,
      subject: 'Reset Your Password',
      text: `Your OTP for password reset is: ${otp}`,
      // Optionally, include an HTML version
      html: `<p>Your OTP for password reset is: <strong>${otp}</strong></p>`,
    };


    // Send email
    await transporter.sendMail(mailOptions);

    console.log(`OTP sent to ${email}`);

    // Update the user document in the database with the new OTP
    const user = await Student.findOneAndUpdate({ email }, { otp }, { new: true });
    if (user) {
      // Send success response
      res.status(200).send({ message: "OTP resent successfully", status: true });
    } else {
      // Send error response if user is not found
      res.status(404).send({ message: "User not found", status: false });
    }
  } catch (error) {
    // Handle errors
    console.error("Error resending OTP:", error);
    res.status(500).send("Internal server error");
  }
};




/**
 * Uploads a file to a cloud storage service (e.g., Cloudinary) and sends back the stored image URL.
 * 
 * @param {Object} req - The request object containing the file to upload in the body.
 * @param {Object} res - The response object to send back to the client.
 */
const uploadFile = (req, res) => {
  // Access the uploaded file using req.file
  const image = req.file;
  if (!image) {
    return res.status(400).json({ message: 'No file uploaded', status: false });
  }

  // Upload the file to Cloudinary or any other storage service
  cloudinary.uploader.upload(image.path, (result, err) => {
    if (err) {
      console.error('Error uploading file:', err);
      return res.status(500).json({ message: 'Error uploading file', status: false });
    }
    // Send back the URL of the uploaded image
    const storedImage = result.secure_url;
    res.json({ message: 'Image uploaded successfully', status: true, storedImage });
  });
};


/**
 * Resets the email verification OTP (One-Time Password) for a user and sends the new OTP to their email address.
 * 
 * @param {Object} req - The request object containing the user's email in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the OTP reset process is complete.
 */
const resetEmail = async (req, res) => {
  const { email } = req.body;
  try {
    // Find the user by email
    const user = await Student.findOne({ email });

    if (user) {
      // Generate a new OTP
      const OTP = generateSixDigitNumber();

      // Save the new OTP to the user document
      user.otp = OTP;
      await user.save();

      // Send the OTP to the user's email
      const mailOptions = {
        from: from,
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is: ${OTP}`
      };
      const mailResponse = await transporter.sendMail(mailOptions);
      console.log('Email sent:', mailResponse);

      // Send success response
      res.status(200).json({ message: 'OTP sent and user updated successfully', status: true });
    } else {
      // User not found
      res.status(404).json({ message: 'User does not exist', status: false });
    }
  } catch (err) {
    // Handle errors
    console.error('Error sending OTP:', err);
    res.status(500).json({ message: 'Oops! Something went wrong', status: false });
  }
};



/**
 * Verifies the OTP (One-Time Password) entered by the user for email verification.
 * 
 * @param {Object} req - The request object containing the OTP code in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the OTP verification process is complete.
 */
const verifyOTP = async (req, res) => {
  const { email, otpCode } = req.body;
  try {
    // Find the user by email
    const user = await Student.findOne({ email });

    if (!user) {
      // User not found
      console.log("User not found");
      return res.status(404).json({ message: "User not found", status: false });
    }

    // Compare the provided OTP code with the user's OTP code
    if (user.otpCode === otpCode) {
      // OTP verified successfully
      console.log("OTP verified");
      return res.status(200).send({ message: "OTP verified successfully", status: true });
    } else {
      // Invalid OTP
      console.log("Invalid OTP");
      return res.status(400).send({ message: "Invalid OTP", status: false });
    }
  } catch (error) {
    // Handle errors
    console.error("Error verifying OTP:", error);
    return res.status(500).send({ message: "Internal server error", status: false });
  }
};





/**
 * Resets the password for a user and updates it in the database.
 * 
 * @param {Object} req - The request object containing the user's email and new password in the body.
 * @param {Object} res - The response object to send back to the client.
 * @returns {Promise<void>} - A promise that resolves once the password reset process is complete.
 */
const resetpassword = async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    // Validate the request payload
    // const validationResult = await schemaValidatorHandler(resetPasswordlPayLoad, { password: newPassword, email });
    // if (!validationResult.valid) {
    //   return res.status(400).json({ message: "Invalid request payload", errors: validationResult.error });
    // }
    if (!email || !newPassword) {
      return res.status(400).json({ message: "Missing required fields", status: false });
    }
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    const user = await Student.findOneAndUpdate({ email }, { password: hashedPassword });

    if (user) {
      // Password reset successful
      return res.status(200).json({ message: 'Password reset successful', status: true });
    } else {
      // User not found
      return res.status(404).json({ message: 'User not found', status: false });
    }
  } catch (error) {
    // Handle errors
    console.error('Error resetting password:', error);
    return res.status(500).json({ message: 'Internal server error', status: false });
  }
};


/**
 * Fetches user details based on the authenticated user's ID.
 * 
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {void}
 */
const getUserDetails = async (req, res) => {
  try {

    // req.auth_id from middle ware
    // Retrieve user details from the database based on the authenticated user's ID
    const userId = req.auth_id; // Assuming you're storing the user ID in the JWT payload
    // console.log(userId);
    const user = await Student.findById(userId).select('-password -otp -__v');
    // console.log({user});   
    // Check if user exists
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // user = excludeFields(user.toObject(), ['password', 'otp', "__v"]);
    return res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};





module.exports = {
  displayWelcome,
  signup,
  login,
  verifyOTP,
  sendOTP,
  resendOTP,
  uploadFile,
  resetEmail,
  resetpassword,
  verifyToken,
  verifyEmail,
  resendSignupOTP,
  getUserDetails
};


require('dotenv').config();
const Student = require("../model/user.model");
const jwt = require("jsonwebtoken")

const TOKEN_MIDDLEWARE = (req, res, next) => {
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
    jwt.verify(token, secretkey, async(err, decoded) => {  
      // Check if token verification failed
      if (err) {
        console.error('Token Verification failed:', err.message);
        return res.status(401).send({ message: 'Unauthorized request, please login', status: false });
      } else {
        const email = decoded.email;
        try {
            const user = await Student.findOne({ email });
            req.auth_email = email
            req.auth_id = user._id;
            next()
        } catch (error) {
            return res.status(401).send({ message: 'Unauthorized request, please login', status: false });
        }
      }
    });
  };


  module.exports = {
    TOKEN_MIDDLEWARE
  }
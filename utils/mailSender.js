const nodemailer = require("nodemailer");
const otpGenerator = require("otp-generator");

const sendOTP = async (email) => {
  try {
    // Generate OTP
    const otp = otpGenerator.generate(4, { upperCase: false, specialChars: false, alphabets: false });

    // Create SMTP transporter
    let transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: 465,
      secure: false,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });

    // Send OTP email
    await transporter.sendMail({
      from: `"User Authentication" ${process.env.MAIL_USER}`,
      to: email,
      subject: "OTP Verification",
      text: `Your OTP for email verification is: ${otp}`,
    });

    // Save OTP in database
    await Student.updateOne({ email: email }, { $set: { otp: otp } });

    return otp;
  } catch (error) {
    console.error("Error sending OTP:", error);
    throw new Error("Error sending OTP");
  }
};

module.exports = sendOTP;

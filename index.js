const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");

dotenv.config();

const app = express();

app.use(express.json());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

//creater user
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
// Create OTP schema
const otpSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 600 }, // OTP will expire after 10 minutes
});

// Create OTP model
const OTP = mongoose.model("OTP", otpSchema);

const User = mongoose.model("User", UserSchema);

app.get("/api",async(req,res)=>{
    return res.status(200).json({ message: "API server" });
})

app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;

  // Generate a salt and hash the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create a new user
  const user = new User({
    username,
    email,
    password: hashedPassword,
  });

  // Save the user to the database
  await user.save();

  return res.status(201).json({ message: "user created" });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  // Find the user by username
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).send("Invalid username or password");
  }
  const email = user.email;
  // Verify the password
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(401).send("Invalid username or password");
  }

  // Generate a 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  // Save the OTP to the database
  const newOTP = new OTP({
    userId: user._id,
    otp,
  });
  await newOTP.save();

  // Send the OTP to the user's email
  const transporter = nodemailer.createTransport({
    host: "smtp-mail.outlook.com",
    port: 587,
    secureConnection: false,
    auth: {
      user: process.env.EMAIL_ADDRESS,
      pass: process.env.EMAIL_PASSWORD,
    },
    tls: {
      ciphers: "SSLv3",
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_ADDRESS,
    to: email,
    subject: "Login OTP Verification",
    text: `Your OTP for login is ${otp}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: "Error sending in email" });
    } else {
      console.log("Email sent: " + info.response);
      return res
        .status(200)
        .json({ message: "Please verify the OTP", id: user._id });
    }
  });
});

app.post("/api/verify-otp", async (req, res) => {
  const { otp, id } = req.body;

  // Verify the OTP from the database
  const otpData = await OTP.findOne({ otp });
  if (!otpData) {
    return res.status(401).json({ message: "Invalid OTP" });
  }

  // Delete the OTP from the database
  await otpData.deleteOne();

  return res.status(200).json({ message: "OTP verified", verify: true });
});

app.post("/api/form-data", async (req, res) => {
  const { name, email, number, message } = req.body;

  // Send the OTP to the user's email
  const transporter = nodemailer.createTransport({
    host: "smtp-mail.outlook.com",
    port: 587,
    secureConnection: false,
    auth: {
      user: process.env.EMAIL_ADDRESS,
      pass: process.env.EMAIL_PASSWORD,
    },
    tls: {
      ciphers: "SSLv3",
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_ADDRESS,
    to: email,
    subject: "karthi interior design",
    text: `
      <span>Name:<i><b>${name}</b></i></span><br />
      <span>E-mail:<i><b>${email}</b></i></span><br />
      <span>Number:<i><b>${number}</b></i></span><br />
      <span>Message:<i><b>${message}</b></i></span><br />
      `,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
      return res.status(500).json({ message: "Error sending in email" });
    } else {
      console.log("Email sent: " + info.response);
      return res
        .status(200)
        .json({ message: "Form data submitted successfully" });
    }
  });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

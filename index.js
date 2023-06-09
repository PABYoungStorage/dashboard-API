const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
const cors = require("cors");

dotenv.config();

const app = express();

app.use(express.json());
app.use(cors());

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
const cardSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true }, // or String, depending on the actual data type
});

const BoardSchema = new mongoose.Schema({
  title: { type: String, require: true },
  cards: { type: [cardSchema], default: [] },
});

// Create OTP model
const OTP = mongoose.model("otp", otpSchema);

const User = mongoose.model("user", UserSchema);

const Board = mongoose.model("board", BoardSchema);

app.get("/", async (req, res) => {
  return res.status(200).json({ message: "Dashboard API server" });
});

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
    return res
      .status(401)
      .json({ message: "Invalid username or password", status: false });
  }
  const email = user.email;
  // Verify the password
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res
      .status(401)
      .json({ message: "Invalid username or password", status: false });
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
      return res
        .status(500)
        .json({ message: "Error sending in email", status: false });
    } else {
      console.log("Email sent: " + info.response);
      return res
        .status(200)
        .json({ message: "Please verify the OTP", status: true });
    }
  });
});

app.post("/api/verify-otp", async (req, res) => {
  const { otp } = req.body;

  // Verify the OTP from the database
  const otpData = await OTP.findOne({ otp });
  if (!otpData) {
    return res.status(401).json({ message: "Invalid OTP", status: false });
  }

  // Delete the OTP from the database
  await otpData.deleteOne();

  return res.status(200).json({ message: "OTP verified", status: true });
});

app.get("/api/users", async (req, res) => {
  const user = await User.find();
  return res.status(200).json({ message: user, status: "true" });
});

app.get("/api/boards", async (req, res) => {
  const user = await Board.find();
  return res.status(200).json({ message: user, status: "true" });
});

// add a card to the backlog array
app.post("/api/boards/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const backlog = await Board.findOne({ id: parseInt(id) });
    const card = req.body;
    backlog.cards.push(card);
    await backlog.save();
    res.status(200).json({ message: "board added", status: true });
  } catch (error) {
    console.log(error);
    res.status(500).send("Error adding card");
  }
});

// delete a card from the backlog array
app.delete("/api/boards/:id/cards/:cardId", async (req, res) => {
  try {
    const id = req.params.id;
    const cardId = req.params.cardId;
    const backlog = await Board.findOne({ id: parseInt(id) });
    const cardIndex = backlog.cards.findIndex((card) => card.id == cardId);
    if (cardIndex === -1) {
      res.status(404).send("Card not found in backlog");
      return;
    }
    backlog.cards.splice(cardIndex, 1);
    await backlog.save();
    res.status(200).json({ message: "card deleted", status: true });
  } catch (error) {
    console.log(error);
    res.status(500).send("Error deleting card");
  }
});

// Move a card from one card array to another
app.post("/api/boards/:id/move/:moveid", async (req, res) => {
  try {
    const id = req.params.id;
    const moveid = req.params.moveid;
    const backlog = await Board.findOne({ id: parseInt(id) });
    const cardbody = req.body;
    if (!backlog) {
      return res.status(404).send("Backlog not found");
    }
    const cardIndex = backlog.cards.findIndex((card) => card.id == cardbody.id);
    if (cardIndex === -1) {
      res.status(404).send("Card not found in backlog");
      return;
    }
    backlog.cards.splice(cardIndex, 1);
    await backlog.save();
    const movelog = await Board.findOne({ id: parseInt(moveid) });
    movelog.cards.push(cardbody);
    await movelog.save();
    res
      .status(200)
      .json({ message: "shift successfully happens", status: true });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

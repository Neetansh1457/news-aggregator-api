const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const NewsAPI = require("newsapi");
const dotenv = require("dotenv");

const app = express();
const port = 3000;

dotenv.config();

mongoose.connect("mongodb://localhost:27017/news_app", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  preferences: {
    sources: String,
    q: String,
    category: String,
    language: String,
    country: String,
  },
});

const User = mongoose.model("User", userSchema);

app.use(bodyParser.json());

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden" });
    }
    req.user = user;
    next();
  });
}

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/preferences", authenticateToken, (req, res) => {
  res.json({ message: "News preferences retrieved successfully" });
});

app.put("/preferences", authenticateToken, (req, res) => {
  res.json({ message: "News preferences updated successfully" });
});

app.get("/news", authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    if (!user.preferences) {
      return res.status(400).json({ message: "User preferences not found" });
    }

    const { sources, q, category, language, country } = user.preferences;
    const newsapi = new NewsAPI(process.env.API_KEY);

    const response = await newsapi.v2.topHeadlines({
      sources,
      q,
      category,
      language,
      country,
    });

    res.json(response);
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

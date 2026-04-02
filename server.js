/**
 * Clothing Store (Express + MongoDB)
 */

const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const morgan = require("morgan");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled promise rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
});

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const DEBUG_ERRORS = NODE_ENV !== "production";
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/clothing_store";
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

/* ---------------- ERROR HANDLING FIX ---------------- */
function clientErrorStatus(err) {
  if (!err) return 500;
  if (err.name === "CastError") return 400;
  if (err.name === "ValidationError") return 400;
  if (err.code === 11000) return 409;

  const msg = err.message?.toLowerCase() || "";

  if (
    err.name === "MongooseServerSelectionError" ||
    err.name === "MongoNetworkError" ||
    (err.name === "MongoServerError" && msg.includes("failed to connect"))
  ) {
    return 503;
  }

  if (
    msg.includes("econnrefused") ||
    msg.includes("timed out") ||
    msg.includes("server selection")
  ) {
    return 503;
  }

  return 500;
}

/* ---------------- MODELS ---------------- */
const { Schema } = mongoose;

const User = mongoose.model("User", new Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String
}));

const Product = mongoose.model("Product", new Schema({
  category: String,
  name: String,
  price: Number,
  imageUrl: String
}));

const Cart = mongoose.model("Cart", new Schema({
  userId: Schema.Types.ObjectId,
  items: [{ productId: Schema.Types.ObjectId, quantity: Number }]
}));

/* ---------------- AUTH ---------------- */
function signToken(user) {
  return jwt.sign({ sub: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.sub;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

/* ---------------- ROUTES ---------------- */

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash: hash });
    res.json({ token: signToken(user) });
  } catch (err) {
    res.status(clientErrorStatus(err)).json({ message: err.message });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const user = await User.findOne({ email });
    const ok = await bcrypt.compare(req.body.password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid" });
    res.json({ token: signToken(user) });
  } catch (err) {
    res.status(500).json({ message: "Login failed" });
  }
});

// Products
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    res.status(clientErrorStatus(err)).json({ message: "Failed" });
  }
});

// Cart
app.post("/api/cart", auth, async (req, res) => {
  try {
    let cart = await Cart.findOne({ userId: req.userId });
    if (!cart) cart = await Cart.create({ userId: req.userId, items: [] });

    cart.items.push(req.body);
    await cart.save();

    res.json({ message: "Added to cart" });
  } catch (err) {
    res.status(clientErrorStatus(err)).json({ message: "Cart error" });
  }
});

/* ---------------- HEALTH CHECK FIX ---------------- */
app.get("/api/health", async (req, res) => {
  try {
    let ping = null;

    if (mongoose.connection.db) {
      try {
        ping = await mongoose.connection.db.admin().ping();
      } catch {}
    }

    res.json({
      mongo: mongoose.connection.readyState,
      ping: !!ping
    });
  } catch {
    res.status(503).json({ message: "DB error" });
  }
});

/* ---------------- STATIC ---------------- */
app.use(express.static(path.join(__dirname, "public")));

/* ---------------- START SERVER ---------------- */
async function start() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.warn("⚠️ MongoDB NOT connected. Running in fallback mode.");
  }

  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
}

start();
// index.js - ReciTech (optimized)
// Requisitos: axios, bcryptjs, body-parser, compression, cors, dotenv, express, express-rate-limit, helmet, mongoose
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import bodyParser from "body-parser";
import compression from "compression";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import axios from "axios";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const app = express();

// ---------- Config (env-friendly) ----------
const PORT = process.env.PORT ? Number(process.env.PORT) : 3001;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/recitech";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey_dev_only";
const IA_API_URL = process.env.IA_API_URL || "";
const MAX_UPLOAD_MB = process.env.MAX_UPLOAD_MB ? Number(process.env.MAX_UPLOAD_MB) : 50;
const MAX_BYTES = MAX_UPLOAD_MB * 1024 * 1024;
const MAX_BASE64_CHARS = Math.ceil((MAX_BYTES * 4) / 3);
const CACHE_TTL_SEC = process.env.CACHE_TTL_SEC ? Number(process.env.CACHE_TTL_SEC) : 300; // 5 min
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").filter(Boolean).length
  ? (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim())
  : [
      "https://recitech.netlify.app",
      "https://recitech-mvp.netlify.app",
      "http://localhost:19006",
      "http://localhost:3000",
    ];

// ---------- Security / Perf Middlewares ----------
app.use(helmet());
app.use(compression());
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
      return callback(new Error("Acesso não permitido pelo CORS"));
    },
    credentials: true,
  })
);

// rate limiter (short window, protects from bursts)
app.use(
  rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 120, // allow 120 req/min per IP
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// body parser with generous limit but controlled by env
app.use(bodyParser.json({ limit: `${MAX_UPLOAD_MB}mb` }));
app.use(bodyParser.urlencoded({ limit: `${MAX_UPLOAD_MB}mb`, extended: true }));

// simple logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - IP:${req.ip}`);
  next();
});

// ---------- Mongoose connection (optimized) ----------
mongoose
  .connect(MONGO_URI, {
    // connection pool and timeouts
    maxPoolSize: 20,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    family: 4,
    // useNewUrlParser/UnifiedTopology are default for modern drivers
  })
  .then(() => console.log("✅ MongoDB conectado"))
  .catch((err) => {
    console.error("❌ Erro MongoDB:", err);
    process.exit(1);
  });

// ---------- Schemas & Models ----------
const userSchema = new mongoose.Schema({
  email: { type: String, index: true, required: true, unique: true },
  password: { type: String, required: true }, // hashed
  cnpj: String,
});
const materialSchema = new mongoose.Schema({
  userId: mongoose.Types.ObjectId,
  type: String,
  quantity: Number,
  pricePerKg: Number,
  photoBase64: String,
  createdAt: { type: Date, default: Date.now },
});
materialSchema.index({ userId: 1, createdAt: -1 });

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);

// ---------- Helpers ----------
const signToken = (user) => jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });

const authMiddleware = (req, res, next) => {
  try {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ success: false, error: "Token ausente" });
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: "Token inválido" });
  }
};

// Simple in-memory cache with TTL and size limit
class SimpleCache {
  constructor(ttlSec = 300, maxItems = 1000) {
    this.ttl = ttlSec * 1000;
    this.maxItems = maxItems;
    this.map = new Map();
  }
  get(key) {
    const it = this.map.get(key);
    if (!it) return null;
    if (Date.now() > it.expire) {
      this.map.delete(key);
      return null;
    }
    return it.value;
  }
  set(key, value) {
    if (this.map.size >= this.maxItems) {
      // evict oldest
      const firstKey = this.map.keys().next().value;
      this.map.delete(firstKey);
    }
    this.map.set(key, { value, expire: Date.now() + this.ttl });
  }
}
const classifyCache = new SimpleCache(CACHE_TTL_SEC, 2000);

// axios instance for IA with timeout
const iaClient = axios.create({
  timeout: 8000,
  headers: { "Content-Type": "application/json" },
});

// ---------- Routes ----------
// Health
app.get("/health", (req, res) => res.json({ success: true, uptime: process.uptime() }));

// Root
app.get("/", (req, res) => res.json({ success: true, msg: "Backend ReciTech online (optimized)" }));

// Register (hash password)
app.post("/register", async (req, res) => {
  try {
    const { email, password, cnpj } = req.body;
    if (!email || !password || !cnpj) return res.status(400).json({ success: false, error: "Campos obrigatórios" });

    const exists = await User.findOne({ email }).lean();
    if (exists) return res.status(400).json({ success: false, error: "Email já cadastrado" });

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const user = new User({ email, password: hashed, cnpj });
    await user.save();
    return res.json({ success: true });
  } catch (err) {
    console.error("register err:", err);
    return res.status(500).json({ success: false, error: "Erro interno" });
  }
});

// Login (bcrypt.compare)
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: "Campos obrigatórios" });

    const user = await User.findOne({ email }).lean();
    if (!user) return res.status(401).json({ success: false, error: "Credenciais inválidas" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ success: false, error: "Credenciais inválidas" });

    const token = signToken(user);
    return res.json({ success: true, accessToken: token });
  } catch (err) {
    console.error("login err:", err);
    return res.status(500).json({ success: false, error: "Erro interno" });
  }
});

// Upload material (expects photoBase64 in body)
app.post("/materials", authMiddleware, async (req, res) => {
  try {
    const { type, quantity, pricePerKg, photoBase64 } = req.body;
    if (!photoBase64) return res.status(400).json({ success: false, error: "Imagem ausente" });

    // remove data URI prefix if present
    const cleanBase64 = photoBase64.includes(",") ? photoBase64.split(",")[1] : photoBase64;

    // quick size check to avoid OOM
    if (cleanBase64.length > MAX_BASE64_CHARS) {
      return res.status(413).json({
        success: false,
        error: `Imagem muito grande. Máximo permitido: ${MAX_UPLOAD_MB} MB.`,
      });
    }

    const material = new Material({
      userId: req.user.id,
      type: type || "desconhecido",
      quantity: Number(quantity) || 1,
      pricePerKg: Number(pricePerKg) || 0,
      photoBase64: cleanBase64,
    });

    await material.save();
    // respond quickly with minimal payload
    return res.json({ success: true, material: { _id: material._id, type: material.type, createdAt: material.createdAt } });
  } catch (err) {
    console.error("materials err:", err);
    return res.status(500).json({ success: false, error: "Erro interno no upload" });
  }
});

// List materials (use lean() for speed)
app.get("/materials", authMiddleware, async (req, res) => {
  try {
    const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 }).lean();
    // do not send full base64 to UI unless explicitly requested to reduce bandwidth (optional)
    const safeMaterials = materials.map(m => ({ _id: m._id, type: m.type, quantity: m.quantity, pricePerKg: m.pricePerKg, createdAt: m.createdAt }));
    return res.json({ success: true, materials: safeMaterials });
  } catch (err) {
    console.error("materials list err:", err);
    return res.status(500).json({ success: false, error: "Erro interno" });
  }
});

// classify proxy to IA with caching & timeout
app.post("/classify", authMiddleware, async (req, res) => {
  try {
    const { photoBase64 } = req.body;
    if (!photoBase64) return res.status(400).json({ success: false, error: "Imagem ausente" });

    const cleanBase64 = photoBase64.includes(",") ? photoBase64.split(",")[1] : photoBase64;
    // dedupe/short-circuit on size
    if (cleanBase64.length > MAX_BASE64_CHARS) {
      return res.status(413).json({ success: false, error: `Imagem muito grande (max ${MAX_UPLOAD_MB} MB)` });
    }

    const hash = crypto.createHash("sha256").update(cleanBase64).digest("hex");
    const cached = classifyCache.get(hash);
    if (cached) return res.json(cached);

    if (!IA_API_URL) {
      return res.status(503).json({ success: false, error: "IA não configurada" });
    }

    // call IA with timeout via axios instance
    try {
      const iaResp = await iaClient.post(`${IA_API_URL.replace(/\/$/, "")}/classify`, { photoBase64: cleanBase64 });
      classifyCache.set(hash, iaResp.data);
      return res.json(iaResp.data);
    } catch (err) {
      console.error("IA call failed:", err.message || err.toString());
      return res.status(503).json({ success: false, error: "Serviço de IA temporariamente indisponível." });
    }
  } catch (err) {
    console.error("classify err:", err);
    return res.status(500).json({ success: false, error: "Erro interno" });
  }
});

// basic feedback route (persist to DB optionally)
app.post("/feedback", authMiddleware, async (req, res) => {
  try {
    // for MVP, just log and return OK (you can store in collection if needed)
    const { text, date } = req.body;
    console.log("FEEDBACK:", { user: req.user?.email, text, date });
    return res.json({ success: true });
  } catch (err) {
    console.error("feedback err:", err);
    return res.status(500).json({ success: false, error: "Erro interno" });
  }
});

// ---------- Graceful shutdown ----------
const server = app.listen(PORT, () => {
  console.log(`✅ Backend (optimized) rodando em http://0.0.0.0:${PORT}`);
});

process.on("SIGINT", () => {
  console.log("SIGINT - shutting down");
  server.close(() => {
    mongoose.disconnect().then(() => process.exit(0));
  });
});
process.on("SIGTERM", () => {
  console.log("SIGTERM - shutting down");
  server.close(() => {
    mongoose.disconnect().then(() => process.exit(0));
  });
});

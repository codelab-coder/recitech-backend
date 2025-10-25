// ============================================================
// 🔹 ReciTech Backend - Versão sem bcrypt (MVP)
// ============================================================

import express from "express";
import cors from "cors";
import helmet from "helmet";
import bodyParser from "body-parser";
import compression from "compression";
import rateLimit from "express-rate-limit";
import axios from "axios";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/recitech";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey_dev_only";
const IA_API_URL = process.env.IA_API_URL || "https://recitech-ia-api.onrender.com";

// ============================================================
// 🔧 Middlewares
// ============================================================
app.use(cors());
app.use(helmet());
app.use(compression());
app.use(bodyParser.json({ limit: "50mb" }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
});
app.use(limiter);

// ============================================================
// 💾 MongoDB
// ============================================================
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB conectado"))
  .catch(err => console.error("❌ Erro MongoDB:", err));

const userSchema = new mongoose.Schema({
  email: String,
  password: String, // texto puro
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

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);

// ============================================================
// 🔐 JWT
// ============================================================
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "Token ausente" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, error: "Token inválido" });
  }
};

// ============================================================
// 🚀 Rotas
// ============================================================
app.get("/", (req, res) => res.json({ success: true, msg: "🚀 Backend ReciTech (sem bcrypt) online" }));

// Registro simples
app.post("/register", async (req, res) => {
  const { email, password, cnpj } = req.body;
  if (!email || !password || !cnpj)
    return res.json({ success: false, error: "Campos obrigatórios" });

  const exists = await User.findOne({ email });
  if (exists) return res.json({ success: false, error: "Email já cadastrado" });

  const user = new User({ email, password, cnpj });
  await user.save();
  res.json({ success: true });
});

// Login direto (sem hash)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.json({ success: false, error: "Campos obrigatórios" });

  const user = await User.findOne({ email, password });
  if (!user)
    return res.json({ success: false, error: "Credenciais inválidas" });

  const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "3d" });
  res.json({ success: true, accessToken: token });
});

// Upload de materiais
app.post("/materials", authMiddleware, async (req, res) => {
  const { type, quantity, pricePerKg, photoBase64 } = req.body;
  if (!photoBase64) return res.status(400).json({ success: false, error: "Imagem ausente" });

  const material = new Material({
    userId: req.user.id,
    type: type || "desconhecido",
    quantity: quantity || 1,
    pricePerKg: pricePerKg || 0,
    photoBase64,
  });

  await material.save();
  res.json({ success: true, material });
});

// Listagem
app.get("/materials", authMiddleware, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 }).lean();
  res.json({ success: true, materials });
});

// Classificação IA
app.post("/classify", authMiddleware, async (req, res) => {
  const { photoBase64 } = req.body;
  try {
    const response = await axios.post(`${IA_API_URL}/classify`, { photoBase64 }, { timeout: 8000 });
    res.json(response.data);
  } catch (err) {
    console.error("Erro IA:", err.message);
    res.status(503).json({ success: false, error: "Serviço de IA indisponível." });
  }
});

// ============================================================
// ▶️ Inicialização
// ============================================================
app.listen(PORT, () => {
  console.log(`✅ Backend (sem bcrypt) rodando em http://0.0.0.0:${PORT}`);
});




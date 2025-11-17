// ============================================================
// 🔹 ReciTech Backend + Upload via FormData
// ============================================================

import express from "express";
import cors from "cors";
import helmet from "helmet";
import bodyParser from "body-parser";
import compression from "compression";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import multer from "multer";
import fs from "fs";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/recitech";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey_dev_only";

// ============================================================
// 🔧 Middlewares
// ============================================================
app.use(cors());
app.use(helmet());
app.use(compression());
app.use(bodyParser.json({ limit: "50mb" }));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 100 });
app.set("trust proxy", 1);
app.use(limiter);

// ============================================================
// 💾 MongoDB
// ============================================================
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB conectado"))
  .catch(err => console.error("❌ Erro MongoDB:", err));

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
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
// 🖼️ Multer para upload de arquivos
// ============================================================
const storage = multer.memoryStorage();
const upload = multer({ storage });

// ============================================================
// 🚀 Rotas
// ============================================================

// Teste
app.get("/", (req, res) => res.json({ success: true, msg: "🚀 Backend ReciTech online" }));

// Registro
app.post("/register", async (req, res) => {
  const { email, password, cnpj } = req.body;
  if (!email || !password || !cnpj) return res.json({ success: false, error: "Campos obrigatórios" });

  const exists = await User.findOne({ email });
  if (exists) return res.json({ success: false, error: "Email já cadastrado" });

  const user = new User({ email, password, cnpj });
  await user.save();
  res.json({ success: true });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ success: false, error: "Campos obrigatórios" });

  const user = await User.findOne({ email, password });
  if (!user) return res.json({ success: false, error: "Credenciais inválidas" });

  const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "3d" });
  res.json({ success: true, accessToken: token });
});

// Upload de materiais (via FormData)
app.post("/materials", authMiddleware, upload.single("photo"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: "Imagem ausente" });

    const { type, quantity, pricePerKg } = req.body;

    // Converte buffer para Base64
    const photoBase64 = req.file.buffer.toString("base64");

    const material = new Material({
      userId: req.user.id,
      type: type || "desconhecido",
      quantity: quantity ? Number(quantity) : 1,
      pricePerKg: pricePerKg ? Number(pricePerKg) : 0,
      photoBase64,
    });

    await material.save();
    res.json({ success: true, material });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Erro no upload" });
  }
});

// Listagem de materiais
app.get("/materials", authMiddleware, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 }).lean();
  res.json({ success: true, materials });
});

// ============================================================
// ▶️ Inicialização
// ============================================================
app.listen(PORT, () => {
  console.log(`✅ Backend rodando em http://0.0.0.0:${PORT}`);
});

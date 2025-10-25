// ============================================================
// 🌱 ReciTech Ultra Fast Backend (v2.2) — Sem Redis
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
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import statusMonitor from "express-status-monitor";
import crypto from "crypto";

dotenv.config();

// ============================================================
// 1. CONFIGURAÇÕES GERAIS
// ============================================================
const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/recitech";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey_dev_only";
const IA_API_URL = process.env.IA_API_URL || "https://recitech-ia-api.onrender.com";

// ============================================================
// 2. CORS (compatível com Expo e navegadores)
// ============================================================
app.use(cors({
  origin: "*", // ✅ libera para todas as origens (teste mobile / Expo)
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// ============================================================
// 3. SEGURANÇA, PERFORMANCE E LOGS
// ============================================================
app.use(helmet());
app.use(compression());
app.use(statusMonitor());
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ============================================================
// 4. MONGODB
// ============================================================
mongoose.connect(MONGO_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 8000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log("✅ MongoDB conectado"))
  .catch(err => console.error("❌ Erro MongoDB:", err));

// ============================================================
// 5. SCHEMAS
// ============================================================
const userSchema = new mongoose.Schema({
  email: String,
  password: String, // hashed
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

const feedbackSchema = new mongoose.Schema({
  userId: mongoose.Types.ObjectId,
  text: String,
  date: Date,
});

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);
const Feedback = mongoose.model("Feedback", feedbackSchema);

// ============================================================
// 6. AUTENTICAÇÃO JWT
// ============================================================
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res.status(401).json({ success: false, error: "Token ausente" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, error: "Token inválido" });
  }
};

// ============================================================
// 7. ROTAS BÁSICAS / STATUS
// ============================================================
app.get("/", (req, res) => {
  res.json({ success: true, msg: "🚀 Backend ReciTech Ultra Fast online" });
});

// ============================================================
// 8. AUTENTICAÇÃO
// ============================================================
app.post("/register", async (req, res) => {
  try {
    const { email, password, cnpj } = req.body;
    if (!email || !password || !cnpj)
      return res.json({ success: false, error: "Campos obrigatórios" });

    const exists = await User.findOne({ email });
    if (exists)
      return res.json({ success: false, error: "Email já cadastrado" });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, cnpj });
    await user.save();

    res.json({ success: true, msg: "Usuário registrado com sucesso" });
  } catch (err) {
    console.error("❌ Erro no registro:", err);
    res.status(500).json({ success: false, error: "Erro interno no registro" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.json({ success: false, error: "Campos obrigatórios" });

    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.json({ success: false, error: "Credenciais inválidas" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "3d" }
    );
    res.json({ success: true, accessToken: token });
  } catch (err) {
    console.error("❌ Erro no login:", err);
    res.status(500).json({ success: false, error: "Erro interno no login" });
  }
});

// ============================================================
// 9. MATERIAIS (UPLOAD / LISTAR)
// ============================================================
const MAX_BYTES = 50 * 1024 * 1024;
const MAX_BASE64_CHARS = Math.ceil((MAX_BYTES * 4) / 3);

app.post("/materials", authMiddleware, async (req, res) => {
  try {
    const { type, quantity, pricePerKg, photoBase64 } = req.body;
    if (!photoBase64)
      return res.status(400).json({ success: false, error: "Imagem ausente" });

    const cleanBase64 = photoBase64.includes(",")
      ? photoBase64.split(",")[1]
      : photoBase64;

    if (cleanBase64.length > MAX_BASE64_CHARS)
      return res
        .status(413)
        .json({ success: false, error: "Imagem muito grande (máx 50MB)" });

    const material = new Material({
      userId: req.user.id,
      type: type || "desconhecido",
      quantity: quantity || 1,
      pricePerKg: pricePerKg || 0,
      photoBase64: cleanBase64,
    });

    await material.save();
    console.log(`📸 Upload OK: ${material.type}`);
    res.json({ success: true, material });
  } catch (err) {
    console.error("❌ Erro no upload:", err);
    res.status(500).json({ success: false, error: "Erro interno no upload" });
  }
});

app.get("/materials", authMiddleware, async (req, res) => {
  try {
    const materials = await Material.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .lean();
    res.json({ success: true, materials });
  } catch (err) {
    console.error("❌ Erro ao listar materiais:", err);
    res.status(500).json({ success: false, error: "Erro interno" });
  }
});

// ============================================================
// 10. CLASSIFICAÇÃO COM IA (sem cache Redis)
// ============================================================
app.post("/classify", authMiddleware, async (req, res) => {
  const { photoBase64 } = req.body;
  if (!photoBase64)
    return res.json({ success: false, error: "Imagem ausente" });

  try {
    const response = await axios.post(`${IA_API_URL}/classify`, { photoBase64 }, { timeout: 12000 });
    res.json(response.data);
  } catch (err) {
    console.error("Erro IA:", err.message);
    res.status(503).json({ success: false, error: "Serviço de IA indisponível" });
  }
});

// ============================================================
// 11. FEEDBACK / REPORT
// ============================================================
app.post("/feedback", authMiddleware, async (req, res) => {
  try {
    const { text, date } = req.body;
    if (!text) return res.json({ success: false, error: "Texto ausente" });
    const fb = new Feedback({ userId: req.user.id, text, date: date || new Date() });
    await fb.save();
    res.json({ success: true });
  } catch (err) {
    console.error("Erro feedback:", err);
    res.status(500).json({ success: false, error: "Erro interno no feedback" });
  }
});

// ============================================================
// 12. INICIAR SERVIDOR
// ============================================================
app.listen(PORT, () =>
  console.log(`✅ Backend (sem Redis) rodando em http://0.0.0.0:${PORT}`)
);



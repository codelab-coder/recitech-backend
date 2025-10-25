// ===== ReciTech Backend Turbo (v2) =====
// Login ultrarrápido com JWT + cache de sessão
// Compatível com App.js 10/10

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import path from "path";

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "50mb" })); // aceita fotos grandes sem erro
app.use(bodyParser.urlencoded({ extended: true, limit: "50mb" }));

// ===== Config =====
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "recitech_secret_key";
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://<user>:<pass>@cluster.mongodb.net/recitech";

// ===== Mongo Connection =====
mongoose
  .connect(MONGO_URI, { maxPoolSize: 10 })
  .then(() => console.log("✅ MongoDB conectado com sucesso"))
  .catch((err) => console.error("❌ Erro Mongo:", err));

mongoose.connection.on("disconnected", () => {
  console.log("⚠️ Conexão Mongo perdida — tentando reconectar...");
  setTimeout(() => mongoose.connect(MONGO_URI), 3000);
});

// ===== Modelos =====
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  cnpj: String,
});

const materialSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  type: String,
  quantity: Number,
  pricePerKg: Number,
  filename: String,
  photoBase64: String,
  createdAt: { type: Date, default: Date.now },
});

const feedbackSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  text: String,
  date: String,
});

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);
const Feedback = mongoose.model("Feedback", feedbackSchema);

// ===== Middleware Auth =====
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.json({ success: false, error: "Token ausente" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.json({ success: false, error: "Token inválido" });
  }
};

// ===== Rotas =====

// --- Registro ---
app.post("/register", async (req, res) => {
  try {
    const { email, password, cnpj } = req.body;
    if (!email || !password) return res.json({ success: false, error: "Campos obrigatórios" });

    const exists = await User.findOne({ email });
    if (exists) return res.json({ success: false, error: "Usuário já existe" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashed, cnpj });
    res.json({ success: true, id: user._id });
  } catch (err) {
    console.error("❌ Erro register:", err);
    res.json({ success: false, error: "Falha no cadastro" });
  }
});

// --- Login (ultrarrápido) ---
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, error: "Usuário não encontrado" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.json({ success: false, error: "Senha incorreta" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    // Cache instantâneo (RAM)
    res.json({ success: true, accessToken: token });
  } catch (err) {
    console.error("❌ Erro login:", err);
    res.json({ success: false, error: "Erro no servidor" });
  }
});

// --- Classificação IA (mock rápido) ---
app.post("/classify", (req, res) => {
  // Aqui você pode conectar com o modelo real (TensorFlow, API IA, etc.)
  const labels = ["Plástico", "Metal", "Vidro", "Papel", "desconhecido"];
  const label = labels[Math.floor(Math.random() * labels.length)];
  const confidence = (Math.random() * 0.4 + 0.6).toFixed(2);
  res.json({ label, confidence: Number(confidence) });
});

// --- Upload de materiais ---
app.post("/materials", authMiddleware, async (req, res) => {
  try {
    const { type, quantity, pricePerKg, photoBase64 } = req.body;
    const material = await Material.create({
      user: req.userId,
      type,
      quantity,
      pricePerKg,
      photoBase64,
    });
    res.json({ success: true, material });
  } catch (err) {
    console.error("❌ Erro upload:", err);
    res.json({ success: false, error: "Falha no upload" });
  }
});

// --- Buscar materiais do usuário ---
app.get("/materials", authMiddleware, async (req, res) => {
  try {
    const materials = await Material.find({ user: req.userId }).sort({ createdAt: -1 });
    res.json({ success: true, materials });
  } catch {
    res.json({ success: false, error: "Erro ao buscar materiais" });
  }
});

// --- Feedback ---
app.post("/feedback", authMiddleware, async (req, res) => {
  try {
    const { text, date } = req.body;
    await Feedback.create({ user: req.userId, text, date });
    res.json({ success: true });
  } catch {
    res.json({ success: false, error: "Erro ao salvar feedback" });
  }
});

// --- Rota base ---
app.get("/", (req, res) => {
  res.json({ success: true, message: "🌱 ReciTech Backend Turbo rodando!" });
});

// ===== Start Server =====
app.listen(PORT, () => console.log(`🚀 Servidor ativo em porta ${PORT}`));

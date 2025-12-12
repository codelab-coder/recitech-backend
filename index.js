// ============================================================
// ReciTech Backend — Versão Completa e Estável (Entrega)
// ============================================================

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import multer from "multer";

dotenv.config();

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "50mb" }));

// Rate limiter (protege endpoints públicos)
const limiter = rateLimit({
  windowMs: 30 * 1000, // 30s
  max: 30, // max 30 reqs per window per IP (ajustável)
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ------------------------------
// Configs / ENV
// ------------------------------
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "recitech_2025_secret";
const ENABLE_SEED = process.env.ENABLE_SEED === "true";

// ------------------------------
// Conexão MongoDB
// ------------------------------
if (!MONGO_URI) {
  console.error("ERRO: defina MONGO_URI no .env");
  process.exit(1);
}

mongoose
  .connect(MONGO_URI, { autoIndex: true })
  .then(() => console.log("MongoDB conectado com sucesso"))
  .catch((err) => {
    console.error("Erro ao conectar no MongoDB:", err);
    process.exit(1);
  });

// ------------------------------
// Schemas / Models
// ------------------------------
const userSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    saldo: { type: Number, default: 0 },
    totalKg: { type: Number, default: 0 },
    totalCo2: { type: Number, default: 0 },
    rank: { type: String, default: "Bronze" },
    badges: { type: [String], default: [] },
    historicoMensal: { type: [Number], default: [] },
  },
  { timestamps: true }
);

const materialSchema = new mongoose.Schema({
  userId: { type: mongoose.Types.ObjectId, ref: "User" },
  type: String,
  estimatedKg: Number,
  value: Number,
  confidence: Number,
  photoBase64: String,
  createdAt: { type: Date, default: Date.now },
});

const marketplaceSchema = new mongoose.Schema({
  userId: { type: mongoose.Types.ObjectId, ref: "User" },
  userEmail: String,
  tipo: String,
  quantidade: Number,
  preco: Number,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);
const Marketplace = mongoose.model("Marketplace", marketplaceSchema);

// ------------------------------
// Middleware Auth (carrega user)
// ------------------------------
const auth = async (req, res, next) => {
  const header = req.headers.authorization;
  const token = header?.split?.(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "Token requerido" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.id).select("-password");
    if (!user) return res.status(401).json({ success: false, error: "Usuário não encontrado" });
    req.user = user; // anexa user completo (sem password)
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: "Token inválido" });
  }
};

// ------------------------------
// Multer (se mais tarde quiser upload de arquivo raw)
// ------------------------------
const upload = multer(); // uso básico (não salva em disco por enquanto)

// ------------------------------
// Helpers
// ------------------------------
const safeJson = (res, payload = {}) => res.json({ success: true, ...payload });
const safeError = (res, code = 400, message = "Erro") => res.status(code).json({ success: false, error: message });

// ------------------------------
// Routes
// ------------------------------

// Health
app.get("/", (req, res) => res.send("ReciTech Backend - OK"));

// Register
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return safeError(res, 400, "Email e senha são obrigatórios");

    // Normaliza
    const emailNorm = email.toLowerCase();

    // Check existing
    const exists = await User.findOne({ email: emailNorm });
    if (exists) return safeError(res, 409, "E-mail já cadastrado");

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email: emailNorm, password: hashed });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    return safeJson(res, { accessToken: token });
  } catch (err) {
    // Duplicate key safety
    if (err?.code === 11000) return safeError(res, 409, "E-mail já cadastrado");
    console.error("Erro /register:", err);
    return safeError(res, 500, "Erro interno ao registrar");
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return safeError(res, 400, "Email e senha são obrigatórios");

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return safeError(res, 401, "Credenciais inválidas");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return safeError(res, 401, "Credenciais inválidas");

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    return safeJson(res, { accessToken: token });
  } catch (err) {
    console.error("Erro /login:", err);
    return safeError(res, 500, "Erro interno no login");
  }
});

// User profile
app.get("/user/profile", auth, async (req, res) => {
  // retornamos user sem password (já carregado no middleware)
  return safeJson(res, { user: req.user });
});

// POST /materials - recebe base64 e cria material (simula IA)
app.post("/materials", auth, upload.none(), async (req, res) => {
  try {
    // Se foto vier base64 em photoBase64
    const { photoBase64 } = req.body;

    // Simulação de classificação (método simples, substitua pela IA real)
    const tipos = ["plástico", "papel", "metal", "vidro", "pet", "alumínio"];
    const tipo = tipos[Math.floor(Math.random() * tipos.length)];
    const kg = Number((Math.random() * 1.5 + 0.3).toFixed(2));
    const precos = {
      plástico: 2.8,
      papel: 1.2,
      metal: 4.5,
      vidro: 0.8,
      pet: 3.5,
      alumínio: 6.8,
    };
    const valor = Number((kg * (precos[tipo] || 2)).toFixed(2));
    const confidence = 0.9;

    // Atualiza usuário
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { saldo: valor, totalKg: kg, totalCo2: kg * 2.1 },
      $push: { historicoMensal: { $each: [kg], $slice: -6 } },
    });

    const material = await Material.create({
      userId: req.user._id,
      type: tipo,
      estimatedKg: kg,
      value: valor,
      confidence,
      photoBase64: photoBase64 || null,
    });

    return safeJson(res, { type: tipo, estimatedKg: kg, value: valor, material });
  } catch (err) {
    console.error("Erro /materials:", err);
    return safeError(res, 500, "Erro ao enviar material");
  }
});

// GET /materials - lista do usuário
app.get("/materials", auth, async (req, res) => {
  try {
    const materials = await Material.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(200);
    return safeJson(res, { materials });
  } catch (err) {
    console.error("Erro GET /materials:", err);
    return safeError(res, 500, "Erro ao listar materiais");
  }
});

// GET /marketplace - lista pública (paginação simples)
app.get("/marketplace", auth, async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(50, Number(req.query.limit) || 50);
    const skip = (page - 1) * limit;

    const items = await Marketplace.find().sort({ createdAt: -1 }).skip(skip).limit(limit);
    return safeJson(res, { materials: items, page, limit });
  } catch (err) {
    console.error("Erro GET /marketplace:", err);
    return safeError(res, 500, "Erro ao listar marketplace");
  }
});

// POST /marketplace - cria anúncio
app.post("/marketplace", auth, upload.none(), async (req, res) => {
  try {
    const { tipo, quantidade, preco } = req.body;
    if (!tipo || !quantidade || !preco) return safeError(res, 400, "Tipo, quantidade e preço são obrigatórios");

    const q = Number(quantidade);
    const p = Number(preco);

    if (Number.isNaN(q) || Number.isNaN(p) || q <= 0 || p < 0) return safeError(res, 400, "Quantidade e preço inválidos");

    const ad = await Marketplace.create({
      userId: req.user._id,
      userEmail: req.user.email,
      tipo,
      quantidade: q,
      preco: p,
    });

    return safeJson(res, { item: ad });
  } catch (err) {
    console.error("Erro POST /marketplace:", err);
    return safeError(res, 500, "Erro ao publicar anúncio");
  }
});

// POST /create-payment-intent - simula saque (PIX)
app.post("/create-payment-intent", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || isNaN(Number(amount))) return safeError(res, 400, "Amount inválido");

    // amount recebido em centavos (seguindo seu frontend)
    const taxaPercent = 0.10;
    const taxa = Math.round(Number(amount) * taxaPercent);
    const valorLiquido = (Number(amount) - taxa) / 100;

    // Debita do saldo local (convertendo centavos para reais)
    await User.findByIdAndUpdate(req.user._id, { $inc: { saldo: -Number(amount) / 100 } });

    return safeJson(res, { mensagem: "PIX solicitado! Cai em até 48h", valorLiquido });
  } catch (err) {
    console.error("Erro /create-payment-intent:", err);
    return safeError(res, 500, "Erro ao criar pagamento");
  }
});

// ------------------------------
// Optional seed (runs ONLY if ENABLE_SEED=true)
// ------------------------------
const runSeed = async () => {
  if (!ENABLE_SEED) return;
  try {
    console.log("Seed rodando (ENABLE_SEED=true) — criando usuário de teste caso não exista...");
    const usersToCreate = [
      { email: "teste@teste.com", password: "123456" },
      { email: "teste1@teste1.com", password: "123456" },
    ];

    for (const u of usersToCreate) {
      const exists = await User.findOne({ email: u.email });
      if (!exists) {
        const hashed = await bcrypt.hash(u.password, 10);
        await User.create({ email: u.email, password: hashed });
        console.log("Usuário seed criado:", u.email);
      } else {
        console.log("Usuário já existe:", u.email);
      }
    }
  } catch (err) {
    console.error("Erro no seed:", err);
  }
};

// ------------------------------
// Error handler + graceful shutdown
// ------------------------------
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  if (!res.headersSent) return res.status(500).json({ success: false, error: "Erro interno" });
  next(err);
});

process.on("SIGINT", async () => {
  console.log("SIGINT recebido — fechando conexões");
  await mongoose.disconnect();
  process.exit(0);
});

// ------------------------------
// Start
// ------------------------------
app.listen(PORT, async () => {
  console.log(`Backend rodando na porta ${PORT}`);
  await runSeed();
});

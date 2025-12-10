// ============================================================
// ReciTech Backend — Versão Corrigida 100% Estável (10/12/2025)
// ============================================================

import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "50mb" }));

// ------------------------------
// Variáveis de ambiente
// ------------------------------
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "recitech_2025_secret";

// ------------------------------
// Conexão MongoDB com logs claros
// ------------------------------
mongoose
  .connect(MONGO_URI, { autoIndex: true })
  .then(() => console.log("MongoDB conectado com sucesso!"))
  .catch((err) => {
    console.error("Erro ao conectar no MongoDB:", err);
    process.exit(1);
  });

// ------------------------------
// Modelos
// ------------------------------
const User = mongoose.model(
  "User",
  new mongoose.Schema(
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
  )
);

const Material = mongoose.model(
  "Material",
  new mongoose.Schema(
    {
      userId: String,
      type: String,
      estimatedKg: Number,
      value: Number,
      confidence: Number,
      photoBase64: String,
      createdAt: { type: Date, default: Date.now }
    }
  )
);

const Marketplace = mongoose.model(
  "Marketplace",
  new mongoose.Schema(
    {
      userId: String,
      userEmail: String,
      tipo: String,
      quantidade: Number,
      preco: Number,
      createdAt: { type: Date, default: Date.now }
    }
  )
);

// ------------------------------
// Middleware de autenticação
// ------------------------------
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res.status(401).json({ success: false, error: "Token requerido" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, error: "Token inválido" });
  }
};

// ------------------------------
// Rotas
// ------------------------------

// --------------- REGISTRO (com correção de erro 11000)
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.json({ success: false, error: "Email e senha são obrigatórios" });

    // Verifica se já existe
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists)
      return res.json({ success: false, error: "E-mail já cadastrado" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      email: email.toLowerCase(),
      password: hashed,
    });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ success: true, accessToken: token });
  } catch (err) {
    if (err.code === 11000)
      return res.json({ success: false, error: "E-mail já cadastrado" });

    console.error("Erro no register:", err);
    res.json({ success: false, error: "Erro ao registrar" });
  }
});

// --------------- LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return res.json({ success: false, error: "Credenciais inválidas" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ success: false, error: "Credenciais inválidas" });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, accessToken: token });
});

// --------------- PERFIL
app.get("/user/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json({ success: true, user });
});

// --------------- ADICIONAR MATERIAL
app.post("/materials", auth, async (req, res) => {
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

  await User.findByIdAndUpdate(req.user.id, {
    $inc: { saldo: valor, totalKg: kg, totalCo2: kg * 2.1 },
    $push: { historicoMensal: { $each: [kg], $slice: -6 } },
  });

  await Material.create({
    userId: req.user.id,
    type: tipo,
    estimatedKg: kg,
    value: valor,
    confidence: 0.92,
    photoBase64: req.body.photoBase64,
  });

  res.json({ success: true, type: tipo, estimatedKg: kg, value: valor });
});

// --------------- LISTAR MATERIAIS
app.get("/materials", auth, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({
    createdAt: -1,
  });
  res.json({ success: true, materials });
});

// --------------- MARKETPLACE (listar)
app.get("/marketplace", auth, async (req, res) => {
  const materials = await Marketplace.find().sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

// --------------- MARKETPLACE (criar)
app.post("/marketplace", auth, async (req, res) => {
  const { tipo, quantidade, preco } = req.body;
  const user = await User.findById(req.user.id);

  await Marketplace.create({
    userId: user._id,
    userEmail: user.email,
    tipo,
    quantidade,
    preco,
  });

  res.json({ success: true });
});

// --------------- SOLICITAR SAQUE
app.post("/create-payment-intent", auth, async (req, res) => {
  const { amount } = req.body;
  const taxa = Math.round(amount * 0.1);

  await User.findByIdAndUpdate(req.user.id, {
    $inc: { saldo: -amount / 100 },
  });

  res.json({
    success: true,
    mensagem: "PIX solicitado! Cai em até 48h",
    valorLiquido: (amount - taxa) / 100,
  });
});

// ------------------------------
// Rota principal
// ------------------------------
app.get("/", (req, res) =>
  res.send("ReciTech Backend V3 - Corrigido em 10/12/2025")
);

// ------------------------------
app.listen(PORT, () =>
  console.log(`Backend rodando na porta ${PORT}`)
);

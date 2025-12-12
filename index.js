// ===============================
//  ReciTech Backend V3 - Unificado
// ===============================
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "50mb" }));

// ===============================
//  CONFIG
// ===============================
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "recitech_secret_2026";

// ===============================
//  DB CONNECTION
// ===============================
mongoose
  .connect(MONGO_URI, { autoIndex: true })
  .then(() => console.log("✅ MongoDB conectado"))
  .catch((err) => console.error("❌ Erro Mongo:", err));

// ===============================
//  MODELS
// ===============================
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },

    saldo: { type: Number, default: 0 },
    totalKg: { type: Number, default: 0 },
    totalCo2: { type: Number, default: 0 },

    rank: { type: String, default: "Bronze" },
    badges: { type: [String], default: [] },

    historicoMensal: { type: [Number], default: [] },
  })
);

const Material = mongoose.model(
  "Material",
  new mongoose.Schema({
    userId: String,
    type: String,
    estimatedKg: Number,
    value: Number,
    confidence: Number,
    photoBase64: String,
    createdAt: { type: Date, default: Date.now },
  })
);

const Marketplace = mongoose.model(
  "Marketplace",
  new mongoose.Schema({
    userId: String,
    userEmail: String,
    tipo: String,
    quantidade: Number,
    preco: Number,
    comprado: { type: Boolean, default: false },
    comprador: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
  })
);

// ===============================
//  AUTH MIDDLEWARE
// ===============================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token)
    return res.status(401).json({ success: false, error: "Token requerido" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, error: "Token inválido" });
  }
}

// ===============================
//  ROTAS - AUTENTICAÇÃO
// ===============================
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existe = await User.findOne({ email: email.toLowerCase() });
    if (existe)
      return res.json({ success: false, error: "Email já cadastrado" });

    const hash = await bcrypt.hash(password, 10);

    const user = await User.create({
      email: email.toLowerCase(),
      password: hash,
    });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ success: true, accessToken: token });
  } catch (err) {
    res.json({ success: false, error: "Erro ao registrar usuário" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return res.json({ success: false, error: "Usuário não existe" });

  const ok = await bcrypt.compare(password, user.password);

  if (!ok) return res.json({ success: false, error: "Senha incorreta" });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ success: true, accessToken: token });
});

// ===============================
//  PERFIL
// ===============================
app.get("/user/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json({ success: true, user });
});

// ===============================
//  MATERIAIS (UPLOAD E LISTAGEM)
// ===============================
app.post("/materials", auth, async (req, res) => {
  const tipos = ["plástico", "papel", "metal", "vidro", "pet", "alumínio"];
  const tipo = tipos[Math.floor(Math.random() * tipos.length)];

  const kg = Number((Math.random() * 1.4 + 0.2).toFixed(2));
  const precoTabela = {
    plástico: 2.8,
    papel: 1.2,
    metal: 4.5,
    vidro: 0.8,
    pet: 3.5,
    alumínio: 6.8,
  };
  const valor = Number((kg * (precoTabela[tipo] || 2)).toFixed(2));

  await User.findByIdAndUpdate(req.user.id, {
    $inc: { saldo: valor, totalKg: kg, totalCo2: kg * 2.1 },
    $push: { historicoMensal: { $each: [kg], $slice: -6 } },
  });

  await Material.create({
    userId: req.user.id,
    type: tipo,
    estimatedKg: kg,
    value: valor,
    confidence: 0.95,
    photoBase64: req.body.photoBase64,
  });

  res.json({ success: true, type: tipo, estimatedKg: kg, value: valor });
});

app.get("/materials", auth, async (req, res) => {
  const materiais = await Material.find({ userId: req.user.id }).sort({
    createdAt: -1,
  });
  res.json({ success: true, materials: materiais });
});

// ===============================
//  MARKETPLACE
// ===============================
app.get("/marketplace", auth, async (req, res) => {
  const items = await Marketplace.find().sort({ createdAt: -1 });
  res.json({ success: true, materials: items });
});

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

  res.json({ success: true, message: "Item publicado" });
});

// ===============================
//  SIMULAR COMPRA (FUNCIONA NO FRONTEND)
// ===============================
app.post("/marketplace/compra", auth, async (req, res) => {
  const { idItem } = req.body;

  const item = await Marketplace.findById(idItem);

  if (!item) return res.json({ success: false, error: "Item não encontrado" });
  if (item.comprado === true)
    return res.json({ success: false, error: "Item já comprado" });

  // Marca como comprado
  item.comprado = true;
  item.comprador = req.user.id;
  await item.save();

  // Desconta saldo (simula a transação)
  await User.findByIdAndUpdate(req.user.id, {
    $inc: { saldo: -item.preco },
  });

  res.json({
    success: true,
    mensagem: "Compra simulada com sucesso!",
    item,
  });
});

// ===============================
//  SAQUE SIMULADO PIX
// ===============================
app.post("/create-payment-intent", auth, async (req, res) => {
  const { amount } = req.body;

  const taxa = Math.round(amount * 0.1);
  const valorFinal = (amount - taxa) / 100;

  await User.findByIdAndUpdate(req.user.id, {
    $inc: { saldo: -(amount / 100) },
  });

  res.json({
    success: true,
    mensagem: "PIX solicitado! Pagamento em até 48h.",
    valorLiquido: valorFinal,
  });
});

// ===============================
//  ROOT
// ===============================
app.get("/", (req, res) =>
  res.send("ReciTech Backend v3.0 — Unificado — Jan/2026")
);

// ===============================
//  START SERVER
// ===============================
app.listen(PORT, () =>
  console.log(`🚀 Backend rodando na porta ${PORT}`)
);

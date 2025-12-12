// ===========================================
// ReciTech Backend — Arquivo Único (A + B + C)
// ===========================================

import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json({ limit: "12mb" }));
app.use(helmet());

// ============================
// RATE LIMIT
// ============================
const limiter = rateLimit({
  windowMs: 20 * 1000,
  max: 20,
});
app.use(limiter);

// ============================
// DB CONNECT
// ============================
mongoose
  .connect(process.env.MONGO_URI, { dbName: "recitech" })
  .then(() => console.log("MongoDB conectado"))
  .catch((err) => console.error(err));

// ============================
// MODELS
// ============================
const UserSchema = new mongoose.Schema({
  email: String,
  password: String,
  saldo: { type: Number, default: 0 },
  totalKg: { type: Number, default: 0 },
  totalCo2: { type: Number, default: 0 },
  rank: { type: String, default: "Bronze" },
  historicoMensal: { type: [Number], default: [0, 0, 0, 0, 0, 0] },
});
const User = mongoose.model("User", UserSchema);

const MaterialSchema = new mongoose.Schema({
  userId: String,
  type: String,
  estimatedKg: Number,
  value: Number,
  photoBase64: String,
  createdAt: { type: Date, default: Date.now },
});
const Material = mongoose.model("Material", MaterialSchema);

const MarketplaceSchema = new mongoose.Schema({
  userId: String,
  tipo: String,
  quantidade: Number,
  preco: Number,
  fotoBase64: String,
  createdAt: { type: Date, default: Date.now },
});
const Marketplace = mongoose.model("Marketplace", MarketplaceSchema);

const PurchaseSchema = new mongoose.Schema({
  buyerId: String,
  sellerId: String,
  itemId: String,
  quantidade: Number,
  total: Number,
  formaPagamento: String,
  status: { type: String, default: "pendente" },
  createdAt: { type: Date, default: Date.now },
});
const Purchase = mongoose.model("Purchase", PurchaseSchema);

// ============================
// AUTH MIDDLEWARE
// ============================
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.json({ success: false, error: "Token ausente" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.json({ success: false, error: "Token inválido" });
  }
};

// ============================
// AUTH ROUTES
// ============================
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const exists = await User.findOne({ email });
  if (exists) return res.json({ success: false, error: "Email já registrado" });

  const hashed = await bcrypt.hash(password, 10);

  const user = await User.create({ email, password: hashed });

  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  return res.json({ success: true, accessToken });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.json({ success: false, error: "Usuário não encontrado" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ success: false, error: "Senha incorreta" });

  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  return res.json({ success: true, accessToken });
});

// ============================
// USER PROFILE
// ============================
app.get("/user/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).lean();
  return res.json({ success: true, user });
});

// ============================
// MATERIAL UPLOAD + FAKE IA
// ============================

const IA_FAKE_PRECOS = {
  plástico: 2.8, pet: 3.5,
  papel: 1.2, papelão: 1.0,
  metal: 4.5, alumínio: 6.8,
  vidro: 0.8, orgânico: 0.3,
  eletrônico: 15.0, bateria: 20.0,
  óleo: 5.0, desconhecido: 0.5
};

app.post("/materials", auth, async (req, res) => {
  const { photoBase64 } = req.body;

  if (!photoBase64) return res.json({ success: false, error: "Sem imagem" });

  // IA FAKE - detecta por random
  const tipos = Object.keys(IA_FAKE_PRECOS);
  const type = tipos[Math.floor(Math.random() * tipos.length)];

  const estimatedKg = Number((Math.random() * 1.2 + 0.2).toFixed(2));
  const value = Number((IA_FAKE_PRECOS[type] * estimatedKg).toFixed(2));

  await Material.create({
    userId: req.user.id,
    type,
    estimatedKg,
    value,
    photoBase64,
  });

  const user = await User.findById(req.user.id);
  user.saldo += value;
  user.totalKg += estimatedKg;
  user.totalCo2 += estimatedKg * 2.1;
  user.save();

  return res.json({ success: true, type, estimatedKg, value });
});

// ============================
// MATERIAL LIST
// ============================
app.get("/materials", auth, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
  return res.json({ success: true, materials });
});

// ============================
// MARKETPLACE CRUD
// ============================
app.post("/marketplace", auth, async (req, res) => {
  const { tipo, quantidade, preco, fotoBase64 } = req.body;

  await Marketplace.create({
    userId: req.user.id,
    tipo, quantidade, preco, fotoBase64,
  });

  return res.json({ success: true });
});

app.get("/marketplace", auth, async (req, res) => {
  const materials = await Marketplace.find().sort({ createdAt: -1 });
  return res.json({ success: true, materials });
});

// ============================
// COMPRA + SIMULAÇÃO PIX
// ============================
app.post("/marketplace/buy", auth, async (req, res) => {
  const { itemId, quantidade, formaPagamento } = req.body;

  const item = await Marketplace.findById(itemId);
  if (!item) return res.json({ success: false, error: "Item não encontrado" });

  if (quantidade > item.quantidade)
    return res.json({ success: false, error: "Quantidade acima do disponível" });

  const total = item.preco * quantidade;

  const compra = await Purchase.create({
    buyerId: req.user.id,
    sellerId: item.userId,
    itemId,
    quantidade,
    total,
    formaPagamento,
  });

  if (formaPagamento === "pix") {
    return res.json({
      success: true,
      purchaseId: compra._id,
      valor: total,
      valorLiquido: total * 0.97,
      mensagem: "PIX simulado — aguardando pagamento"
    });
  }

  // COMPRA SIMULADA
  item.quantidade -= quantidade;
  await item.save();

  return res.json({ success: true, message: "Compra simulada concluída" });
});

// ============================
// PIX SAQUE
// ============================
app.post("/create-payment-intent", auth, async (req, res) => {
  const { amount } = req.body;
  const user = await User.findById(req.user.id);

  const valor = amount / 100;

  if (valor > user.saldo)
    return res.json({ success: false, error: "Saldo insuficiente" });

  user.saldo -= valor;
  user.save();

  return res.json({
    success: true,
    message: "Saque PIX solicitado (simulado)."
  });
});

// ============================
// START SERVER
// ============================
app.listen(3000, () => console.log("ReciTech Backend rodando na porta 3000"));

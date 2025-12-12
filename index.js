/**
 * index.js - ReciTech Backend (versão final para MVP)
 * - Registro / Login (bcrypt + JWT)
 * - Models: User, Material, Marketplace, Purchase
 * - Rotas: /register, /login, /user/profile, /materials, /marketplace, /marketplace/buy, /create-payment-intent
 * - Segurança básica: helmet, rate-limit, validation, tratamento de duplicate key
 * - Aceita fotoBase64 em marketplace
 *
 * Ajuste: coloque MONGO_URI e JWT_SECRET no .env
 */

import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" })); // ajuste conforme necessidade (imagens base64)
app.use(helmet());

// Rate limiter - básica
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(limiter);

const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/recitech";
const JWT_SECRET = process.env.JWT_SECRET || "recitech2025_secret_key_2025";

mongoose.connect(MONGO_URI, { })
  .then(() => console.log("MongoDB conectado"))
  .catch(err => { console.error("Erro Mongo:", err); process.exit(1); });

/* ===========================
   MODELS
   ===========================*/
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true, lowercase: true, index: true },
  password: { type: String, required: true },
  saldo: { type: Number, default: 0 },
  totalKg: { type: Number, default: 0 },
  totalCo2: { type: Number, default: 0 },
  rank: { type: String, default: "Bronze" },
  badges: { type: [String], default: [] },
  historicoMensal: { type: [Number], default: [] },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

const materialSchema = new mongoose.Schema({
  userId: String,
  type: String,
  estimatedKg: Number,
  value: Number,
  confidence: Number,
  photoBase64: String,
  createdAt: { type: Date, default: Date.now }
});

const Material = mongoose.model("Material", materialSchema);

const marketplaceSchema = new mongoose.Schema({
  userId: String,
  userEmail: String,
  tipo: String,
  quantidade: Number,
  preco: Number,
  fotoBase64: String,
  createdAt: { type: Date, default: Date.now }
});

const Marketplace = mongoose.model("Marketplace", marketplaceSchema);

const purchaseSchema = new mongoose.Schema({
  itemId: String,
  sellerId: String,
  sellerEmail: String,
  buyerId: String,
  buyerEmail: String,
  quantidade: Number,
  precoUnit: Number,
  total: Number,
  formaPagamento: { type: String, enum: ["simulado","pix"], default: "simulado" },
  status: { type: String, enum: ["pending","completed","failed","cancelled"], default: "pending" },
  createdAt: { type: Date, default: Date.now }
});

const Purchase = mongoose.model("Purchase", purchaseSchema);

/* ===========================
   HELPERS / MIDDLEWARES
   ===========================*/
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "Token requerido" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: "Token inválido" });
  }
};

const safeHandler = (fn) => (req, res) => {
  Promise.resolve(fn(req, res)).catch(err => {
    console.error("Erro interno:", err);
    if (err?.code === 11000) {
      // duplicate key
      return res.status(400).json({ success: false, error: "Registro duplicado" });
    }
    res.status(500).json({ success: false, error: "Erro interno do servidor" });
  });
};

/* ===========================
   ROUTES
   ===========================*/

// health
app.get("/", (req, res) => res.send("ReciTech Backend - Ready"));

// register
app.post("/register", safeHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, error: "Email e senha são obrigatórios" });
  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ email: email.toLowerCase(), password: hashed });
  const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, accessToken: token });
}));

// login
app.post("/login", safeHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, error: "Email e senha são obrigatórios" });
  const user = await User.findOne({ email: email.toLowerCase() });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, accessToken: token });
  } else res.status(401).json({ success: false, error: "Credenciais inválidas" });
}));

// profile
app.get("/user/profile", auth, safeHandler(async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  if (!user) return res.status(404).json({ success: false, error: "Usuário não encontrado" });
  res.json({ success: true, user });
}));

// materials (upload simulated IA result)
app.post("/materials", auth, safeHandler(async (req, res) => {
  const tipos = ["plástico", "papel", "metal", "vidro", "pet", "alumínio"];
  const tipo = tipos[Math.floor(Math.random() * tipos.length)];
  const kg = Number((Math.random() * 1.5 + 0.3).toFixed(2));
  const preco = { plástico: 2.8, papel: 1.2, metal: 4.5, vidro: 0.8, pet: 3.5, alumínio: 6.8 }[tipo] || 2.0;
  const valor = Number((kg * preco).toFixed(2));

  await User.findByIdAndUpdate(req.user.id, {
    $inc: { saldo: valor, totalKg: kg, totalCo2: kg * 2.1 },
    $push: { historicoMensal: { $each: [kg], $slice: -6 } },
  });

  const material = await Material.create({ userId: req.user.id, type: tipo, estimatedKg: kg, value: valor, confidence: 0.92, photoBase64: req.body.photoBase64 });
  res.json({ success: true, type: tipo, estimatedKg: kg, value: valor, material });
}));

// list materials
app.get("/materials", auth, safeHandler(async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(50);
  res.json({ success: true, materials });
}));

/* ===========================
   Marketplace endpoints
   ===========================*/

// publish marketplace item
app.post("/marketplace", auth, safeHandler(async (req, res) => {
  const { tipo, quantidade, preco, fotoBase64 } = req.body;
  if (!tipo || !quantidade || !preco) return res.status(400).json({ success: false, error: "tipo, quantidade e preco são obrigatórios" });

  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ success: false, error: "Usuário não encontrado" });

  const entry = await Marketplace.create({
    userId: req.user.id,
    userEmail: user.email,
    tipo,
    quantidade,
    preco,
    fotoBase64: fotoBase64 || undefined
  });

  res.json({ success: true, item: entry });
}));

// list marketplace items
app.get("/marketplace", auth, safeHandler(async (req, res) => {
  const items = await Marketplace.find().sort({ createdAt: -1 }).limit(200);
  res.json({ success: true, materials: items });
}));

/* ===========================
   PURCHASE FLOW (SIMULATED + PIX)
   POST /marketplace/buy
   Body: { itemId, quantidade, formaPagamento: "simulado" | "pix" }
   ===========================*/
app.post("/marketplace/buy", auth, safeHandler(async (req, res) => {
  const { itemId, quantidade = 1, formaPagamento = "simulado" } = req.body;
  if (!itemId) return res.status(400).json({ success: false, error: "itemId obrigatório" });
  const item = await Marketplace.findById(itemId);
  if (!item) return res.status(404).json({ success: false, error: "Item não encontrado" });
  if (quantidade <= 0) return res.status(400).json({ success: false, error: "Quantidade inválida" });
  if (quantidade > item.quantidade) return res.status(400).json({ success: false, error: "Quantidade solicitada maior que disponível" });

  const buyer = await User.findById(req.user.id);
  if (!buyer) return res.status(404).json({ success: false, error: "Usuário não encontrado" });

  const total = Number((quantidade * item.preco).toFixed(2));

  // If PIX selected, create payment intent (simulated) and mark purchase pending
  if (formaPagamento === "pix") {
    // simulate creating a payment intent (you can integrate real PSP here)
    const taxa = Math.round(total * 0.10 * 100) / 100; // 10% taxa sample
    // create purchase pending
    const purchase = await Purchase.create({
      itemId: item._id.toString(),
      sellerId: item.userId,
      sellerEmail: item.userEmail,
      buyerId: buyer._id.toString(),
      buyerEmail: buyer.email,
      quantidade,
      precoUnit: item.preco,
      total,
      formaPagamento: "pix",
      status: "pending"
    });

    // For simulation: respond with payment instructions
    return res.json({
      success: true,
      mensagem: "PIX criado (simulado). Aguardando confirmação do pagamento.",
      purchaseId: purchase._id,
      valor: total,
      valorLiquido: Number((total - taxa).toFixed(2)),
      prazo: "Até 48h para confirmar (simulado)"
    });
  }

  // formaPagamento === 'simulado' -> complete immediately: transfer between buyer & seller (simulado)
  const purchase = await Purchase.create({
    itemId: item._id.toString(),
    sellerId: item.userId,
    sellerEmail: item.userEmail,
    buyerId: buyer._id.toString(),
    buyerEmail: buyer.email,
    quantidade,
    precoUnit: item.preco,
    total,
    formaPagamento: "simulado",
    status: "completed"
  });

  // reduce item quantidade atomically
  item.quantidade = item.quantidade - quantidade;
  await item.save();

  // credit seller's saldo (simulate instant credit minus marketplace fee 5%)
  const marketplaceFee = Number((total * 0.05).toFixed(2));
  const sellerNet = Number((total - marketplaceFee).toFixed(2));
  if (item.userId) {
    await User.findByIdAndUpdate(item.userId, { $inc: { saldo: sellerNet, totalKg: 0 } });
  }

  // optionally debit buyer? In simulation we don't debit buyer.saldo (since payment external)
  // Respond purchase success
  res.json({ success: true, purchaseId: purchase._id, mensagem: "Compra simulada realizada com sucesso", total });
}));

/* ===========================
   Endpoint to simulate payment confirmation (for PIX flows)
   Call this endpoint to mark pending purchase as completed (simulate webhook)
   POST /marketplace/confirm-pix
   Body: { purchaseId }
   ===========================*/
app.post("/marketplace/confirm-pix", auth, safeHandler(async (req, res) => {
  const { purchaseId } = req.body;
  if (!purchaseId) return res.status(400).json({ success: false, error: "purchaseId obrigatório" });
  const p = await Purchase.findById(purchaseId);
  if (!p) return res.status(404).json({ success: false, error: "Compra não encontrada" });
  if (p.status !== "pending") return res.status(400).json({ success: false, error: "Compra não está em pending" });

  // finalize: reduce item quantity, credit seller
  const item = await Marketplace.findById(p.itemId);
  if (!item) return res.status(404).json({ success: false, error: "Item não encontrado" });
  if (p.quantidade > item.quantidade) return res.status(400).json({ success: false, error: "Quantidade insuficiente no estoque" });

  item.quantidade -= p.quantidade;
  await item.save();

  const marketplaceFee = Number((p.total * 0.05).toFixed(2));
  const sellerNet = Number((p.total - marketplaceFee).toFixed(2));
  if (p.sellerId) {
    await User.findByIdAndUpdate(p.sellerId, { $inc: { saldo: sellerNet } });
  }

  p.status = "completed";
  await p.save();

  res.json({ success: true, mensagem: "Compra PIX confirmada (simulada) e concluída", purchase: p });
}));

/* ===========================
   create-payment-intent (existing)
   This keeps behavior you had: receives amount (cents) and "debita" saldo (simulated)
   ===========================*/
app.post("/create-payment-intent", auth, safeHandler(async (req, res) => {
  const { amount } = req.body; // expected cents (ex: 1000 -> R$10)
  if (!amount) return res.status(400).json({ success: false, error: "amount obrigatório" });

  const taxa = Math.round(amount * 0.10);
  // simulate: subtract from user saldo a quantia convertida
  await User.findByIdAndUpdate(req.user.id, { $inc: { saldo: -(amount / 100) } });

  res.json({ success: true, mensagem: "PIX solicitado! Cai em até 48h", valorLiquido: (amount - taxa) / 100 });
}));

/* ===========================
   Admin / debug: list purchases
   ===========================*/
app.get("/purchases", auth, safeHandler(async (req, res) => {
  const list = await Purchase.find().sort({ createdAt: -1 }).limit(200);
  res.json({ success: true, purchases: list });
}));

/* ===========================
   Error handling fallback
   ===========================*/
app.use((req, res) => res.status(404).json({ success: false, error: "Rota não encontrada" }));

app.listen(PORT, () => console.log(`Backend rodando na porta ${PORT}`));

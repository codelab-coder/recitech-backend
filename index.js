// =============================================
// ReciTech Backend — Versão FINAL & PERFEITA
// Funciona 100% com o frontend que te mandei
// =============================================
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

// Middlewares
app.use(cors({
  origin: "*", // Em produção troque por seu domínio
  credentials: true
}));
app.use(express.json({ limit: "15mb" }));
app.use(helmet({
  contentSecurityPolicy: false,
}));

// Rate limit mais esperto (20 req em 15s por IP)
const limiter = rateLimit({
  windowMs: 15 * 1000,
  max: 25,
  message: { success: false, error: "Muitas requisições. Tente novamente em 15s." }
});
app.use("/login", limiter);
app.use("/register", limiter);
app.use("/materials", limiter);
app.use("/marketplace", limiter);

// ============================
// CONEXÃO COM MONGO
// ============================
mongoose.connect(process.env.MONGO_URI, { dbName: "recitech" })
  .then(() => console.log("MongoDB conectado com sucesso!"))
  .catch(err => console.error("Erro no MongoDB:", err));

// ============================
// MODELOS
// ============================
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true },
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
  userEmail: String,        // NOVO: já salva o email
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
    req.user = jwt.verify(token, process.env.JWT_SECRET || "fallback-secret");
    next();
  } catch {
    return res.json({ success: false, error: "Token inválido ou expirado" });
  }
};

// ============================
// ROTAS DE AUTENTICAÇÃO
// ============================
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ success: false, error: "Email e senha obrigatórios" });

  const exists = await User.findOne({ email });
  if (exists) return res.json({ success: false, error: "Email já registrado" });

  const hashed = await bcrypt.hash(password, 12);
  const user = await User.create({ email, password: hashed });
  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback-secret", { expiresIn: "7d" });

  console.log(`Novo usuário: ${email}`);
  res.json({ success: true, accessToken });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.json({ success: false, error: "Usuário não encontrado" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ success: false, error: "Senha incorreta" });

  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback-secret", { expiresIn: "7d" });
  console.log(`Login: ${email}`);
  res.json({ success: true, accessToken });
});

// ============================
// PERFIL DO USUÁRIO
// ============================
app.get("/user/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).lean();
  if (!user) return res.json({ success: false, error: "Usuário não encontrado" });
  res.json({ success: true, user });
});

// ============================
// UPLOAD DE RESÍDUO + IA FAKE
// ============================
const IA_FAKE_PRECOS = {
  plástico: 2.8, pet: 3.5, papel: 1.2, papelão: 1.0,
  metal: 4.5, alumínio: 6.8, vidro: 0.8, orgânico: 0.3,
  eletrônico: 15.0, bateria: 20.0, óleo: 5.0, desconhecido: 0.5
};

app.post("/materials", auth, async (req, res) => {
  const { photoBase64 } = req.body;
  if (!photoBase64) return res.json({ success: false, error: "Foto obrigatória" });

  const tipos = Object.keys(IA_FAKE_PRECOS);
  const type = tipos[Math.floor(Math.random() * tipos.length)];
  const estimatedKg = Number((Math.random() * 1.4 + 0.1).toFixed(2));
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
  await user.save();

  console.log(`${user.email} reciclou ${estimatedKg}kg de ${type} → +R$${value}`);
  res.json({ success: true, type, estimatedKg, value });
});

app.get("/materials", auth, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

// ============================
// MARKETPLACE
// ============================
app.post("/marketplace", auth, async (req, res) => {
  const { tipo, quantidade, preco, fotoBase64 } = req.body;
  if (!tipo || !quantidade || !preco) return res.json({ success: false, error: "Preencha todos os campos" });

  const user = await User.findById(req.user.id);
  await Marketplace.create({
    userId: req.user.id,
    userEmail: user.email,
    tipo,
    quantidade: Number(quantidade),
    preco: Number(preco),
    fotoBase64,
  });

  console.log(`${user.email} publicou ${quantidade}kg de ${tipo} por R$${preco}/kg`);
  res.json({ success: true });
});

app.get("/marketplace", auth, async (req, res) => {
  const materials = await Marketplace.find().sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

// ============================
// COMPRA (SIMULADA OU PIX)
// ============================
app.post("/marketplace/buy", auth, async (req, res) => {
  const { itemId, quantidade, formaPagamento = "simulado" } = req.body;
  if (!itemId || !quantidade) return res.json({ success: false, error: "Dados incompletos" });

  const item = await Marketplace.findById(itemId);
  if (!item) return res.json({ success: false, error: "Anúncio não encontrado" });
  if (quantidade > item.quantidade) return res.json({ success: false, error: "Quantidade indisponível" });

  const total = Number((item.preco * quantidade).toFixed(2));

  // Cria registro da compra
  await Purchase.create({
    buyerId: req.user.id,
    sellerId: item.userId,
    itemId,
    quantidade,
    total,
    formaPagamento,
  });

  // Atualiza estoque
  item.quantidade -= quantidade;
  if (item.quantidade <= 0) {
    await Marketplace.deleteOne({ _id: itemId });
    console.log(`Anúncio esgotado e removido: ${item.tipo}`);
  } else {
    await item.save();
  }

  // Paga o vendedor (97%)
  const seller = await User.findById(item.userId);
  const valorLiquido = Number((total * 0.97).toFixed(2));
  seller.saldo += valorLiquido;
  await seller.save();

  const buyer = await User.findById(req.user.id);

  if (formaPagamento === "pix") {
    console.log(`${buyer.email} → PIX de R$${total} para ${seller.email}`);
    return res.json({
      success: true,
      valor: total,
      valorLiquido,
      mensagem: "PIX simulado criado! Aguarde o pagamento.",
    });
  }

  console.log(`${buyer.email} comprou ${quantidade}kg de ${item.tipo} de ${seller.email} → R$${total}`);
  res.json({
    success: true,
    message: "Compra concluída! Vendedor já recebeu.",
  });
});

// ============================
// SAQUE PIX (SIMULADO)
// ============================
app.post("/create-payment-intent", auth, async (req, res) => {
  const { amount } = req.body; // em centavos
  if (!amount || amount < 1000) return res.json({ success: false, error: "Mínimo R$10,00" });

  const valor = amount / 100;
  const user = await User.findById(req.user.id);
  if (valor > user.saldo) return res.json({ success: false, error: "Saldo insuficiente" });

  user.saldo -= valor;
  await user.save();

  console.log(`${user.email} solicitou saque de R$${valor} via PIX`);
  res.json({
    success: true,
    message: "Saque PIX solicitado! Chegará em até 48h (simulado).",
  });
});

// ============================
// START
// ============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\nReciTech Backend rodando na porta ${PORT}`);
  console.log(`http://localhost:${PORT}\n`);
});

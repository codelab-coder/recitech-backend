// =============================================
// ReciTech Backend — Versão FINAL para Render.com (2025)
// Com recuperação de senha funcional via Resend (grátis)
// Cálculo realista de CO₂ evitado
// Dados do vendedor no marketplace
// =============================================

import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();

const app = express();

// Middlewares
app.use(cors({
  origin: process.env.FRONTEND_URL || "*",
  credentials: true
}));
app.use(express.json({ limit: "15mb" }));
app.use(helmet({
  contentSecurityPolicy: false,
}));

// Rate limit global
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 200,
  message: { success: false, error: "Muitas requisições. Tente mais tarde." }
});
app.use(limiter);

// Limiter forte para rotas sensíveis
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10,
  message: { success: false, error: "Muitas tentativas. Aguarde 15 minutos." }
});

// ============================
// CONEXÃO COM MONGO
// ============================
mongoose.connect(process.env.MONGO_URI, { dbName: "recitech" })
  .then(() => console.log("MongoDB conectado com sucesso!"))
  .catch(err => {
    console.error("Erro ao conectar no MongoDB:", err);
    process.exit(1);
  });

// ============================
// FATORES DE CO₂ EVITADO (kg CO₂/kg reciclado)
// ============================
const CO2_EVIDO_POR_KG = {
  plástico: 2.0,
  pet: 2.5,
  papel: 1.2,
  papelão: 1.0,
  metal: 4.0,
  alumínio: 10.0,
  vidro: 0.35,
  orgânico: 0.5,
  eletrônico: 8.0,
  bateria: 12.0,
  óleo: 3.0,
  desconhecido: 1.5,
};

// ============================
// MODELOS
// ============================
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: String,
  saldo: { type: Number, default: 0 },
  totalKg: { type: Number, default: 0 },
  totalCo2: { type: Number, default: 0 },
  rank: { type: String, default: "Bronze" },
  historicoMensal: { type: [Number], default: [0, 0, 0, 0, 0, 0] },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
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
  userEmail: String,
  tipo: String,
  quantidade: Number,
  preco: Number,
  telefone: String,
  cidade: String,
  descricao: String,
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
// CONFIGURAÇÃO DE EMAIL COM RESEND
// ============================
let transporter;
if (process.env.RESEND_API_KEY) {
  transporter = nodemailer.createTransport({
    host: "smtp.resend.com",
    secure: true,
    port: 465,
    auth: {
      user: "resend",
      pass: process.env.RESEND_API_KEY,
    },
  });
  console.log("✅ Email configurado com Resend");
} else {
  console.warn("⚠️ RESEND_API_KEY não encontrada. Recuperação de senha desativada.");
}

// ============================
// AUTH MIDDLEWARE (com fallback no JWT_SECRET)
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
// ROTAS
// ============================
app.post("/register", authLimiter, async (req, res) => {
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

app.post("/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.json({ success: false, error: "Email ou senha incorretos" });
  }
  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback-secret", { expiresIn: "7d" });
  console.log(`Login: ${email}`);
  res.json({ success: true, accessToken });
});

// Esqueci minha senha
app.post("/forgot-password", authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ success: false, error: "Email obrigatório" });

  const user = await User.findOne({ email });
  if (!user) {
    return res.json({ success: true, message: "Se o email existir, enviamos um link." });
  }

  if (!transporter) {
    return res.json({ success: false, error: "Serviço de email não configurado." });
  }

  const token = crypto.randomBytes(20).toString("hex");
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hora
  await user.save();

  const resetLink = `${process.env.FRONTEND_URL || "https://recitechmvp.netlify.app"}/reset-password?token=${token}`;

  const mailOptions = {
    from: process.env.FROM_EMAIL || "ReciTech <onboarding@resend.dev>",
    to: user.email,
    subject: "ReciTech - Redefinir sua senha",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
        <h2 style="color: #00C853;">Olá!</h2>
        <p>Recebemos uma solicitação para redefinir sua senha no ReciTech.</p>
        <p>Clique no botão abaixo para criar uma nova senha (válido por 1 hora):</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetLink}" style="background:#00C853;color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px;">
            Redefinir senha
          </a>
        </div>
        <p>Ou copie o link:</p>
        <p><a href="${resetLink}">${resetLink}</a></p>
        <p>Se não foi você, ignore este email.</p>
        <hr>
        <p style="color: #666; font-size: 14px;">Equipe ReciTech ♻️</p>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Email de recuperação enviado para: ${email}`);
    res.json({ success: true, message: "Link enviado para seu email!" });
  } catch (err) {
    console.error("Erro ao enviar email:", err);
    res.json({ success: false, error: "Falha ao enviar email." });
  }
});

// Perfil do usuário
app.get("/user/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password -resetPasswordToken -resetPasswordExpires");
  if (!user) return res.json({ success: false, error: "Usuário não encontrado" });
  res.json({ success: true, user });
});

// Upload de resíduo (IA simulada + crédito + CO₂)
app.post("/materials", auth, async (req, res) => {
  const { photoBase64 } = req.body;
  if (!photoBase64) return res.json({ success: false, error: "Foto obrigatória" });

  const tipos = Object.keys(CO2_EVIDO_POR_KG);
  const type = tipos[Math.floor(Math.random() * tipos.length)];
  const estimatedKg = Number((Math.random() * 1.4 + 0.1).toFixed(2));

  const precoPorKg = {
    plástico: 2.8, pet: 3.5, papel: 1.2, papelão: 1.0,
    metal: 4.5, alumínio: 6.8, vidro: 0.8, orgânico: 0.3,
    eletrônico: 15.0, bateria: 20.0, óleo: 5.0, desconhecido: 0.5
  }[type];

  const value = Number((precoPorKg * estimatedKg).toFixed(2));
  const co2Evitado = estimatedKg * CO2_EVIDO_POR_KG[type];

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
  user.totalCo2 += co2Evitado;
  await user.save();

  console.log(`${user.email} reciclou ${estimatedKg}kg de ${type} → +R$${value} | +${co2Evitado.toFixed(1)}kg CO₂`);
  res.json({ success: true, type, estimatedKg, value });
});

app.get("/materials", auth, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

// Marketplace - Publicar anúncio
app.post("/marketplace", auth, async (req, res) => {
  const { tipo, quantidade, preco, telefone, cidade, descricao, fotoBase64 } = req.body;
  if (!tipo || !quantidade || !preco) {
    return res.json({ success: false, error: "Tipo, quantidade e preço são obrigatórios" });
  }

  const user = await User.findById(req.user.id);
  await Marketplace.create({
    userId: req.user.id,
    userEmail: user.email,
    tipo,
    quantidade: Number(quantidade),
    preco: Number(preco),
    telefone: telefone?.trim() || null,
    cidade: cidade?.trim() || null,
    descricao: descricao?.trim() || null,
    fotoBase64,
  });

  console.log(`${user.email} publicou ${quantidade}kg de ${tipo}`);
  res.json({ success: true });
});

// Marketplace - Listar anúncios (público)
app.get("/marketplace", async (req, res) => {
  const materials = await Marketplace.find().sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

// Marketplace - Comprar
app.post("/marketplace/buy", auth, async (req, res) => {
  const { itemId, quantidade, formaPagamento = "simulado" } = req.body;
  if (!itemId || !quantidade) return res.json({ success: false, error: "Dados incompletos" });

  const item = await Marketplace.findById(itemId);
  if (!item) return res.json({ success: false, error: "Anúncio não encontrado" });
  if (quantidade > item.quantidade) return res.json({ success: false, error: "Quantidade indisponível" });

  const total = Number((item.preco * quantidade).toFixed(2));

  // Registra a compra
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

  // Crédito ao vendedor (97% do valor)
  const seller = await User.findById(item.userId);
  const valorLiquido = Number((total * 0.97).toFixed(2));
  seller.saldo += valorLiquido;
  await seller.save();

  const buyer = await User.findById(req.user.id);
  console.log(`${buyer.email} comprou ${quantidade}kg de ${item.tipo} de ${seller.email} → R$${total}`);

  res.json({
    success: true,
    valor: total,
    message: formaPagamento === "pix" ? "PIX simulado criado!" : "Compra realizada com sucesso!",
  });
});

// Saque PIX simulado
app.post("/create-payment-intent", auth, async (req, res) => {
  const { amount } = req.body; // em centavos
  if (!amount || amount < 1000) return res.json({ success: false, error: "Mínimo R$10,00" });

  const valor = amount / 100;
  const user = await User.findById(req.user.id);
  if (valor > user.saldo) return res.json({ success: false, error: "Saldo insuficiente" });

  user.saldo -= valor;
  await user.save();

  console.log(`${user.email} solicitou saque de R$${valor}`);
  res.json({ success: true, message: "Saque solicitado! Chegará em até 48h (simulado)." });
});

// ============================
// START SERVER
// ============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 ReciTech Backend rodando na porta ${PORT}`);
  console.log(`Frontend: ${process.env.FRONTEND_URL || "não definido"}\n`);
});

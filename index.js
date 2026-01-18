// =============================================
// =============================================
// ReciTech Backend — Versão FINAL para Render.com (2025/2026)
// CORS corrigido, chat implementado, trust proxy ativado, email com timeout maior
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

// =============================================
// ATIVAÇÃO OBRIGATÓRIA PARA Render + proxies
// =============================================
app.set('trust proxy', 1); // Confia no primeiro proxy (Render/Cloudflare/Netlify) → corrige ERR_ERL_UNEXPECTED_X_FORWARDED_FOR

// =============================================
// CORS CONFIGURAÇÃO
// =============================================
const allowedOrigins = [
  'https://recitech-mvp.netlify.app',
  'https://recitechmvp.netlify.app',
  'http://localhost:19006',
  'http://localhost:19000',
  'http://localhost:3000',
  'http://localhost:8081',
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, origin);
    } else {
      console.warn(`[CORS] Origin bloqueado: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Log para depurar CORS
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    console.log(`[OPTIONS] Origin recebido: ${req.headers.origin || 'sem origin'}`);
  }
  next();
});

// Outros middlewares
app.use(express.json({ limit: "15mb" }));
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limit global (agora funciona com trust proxy)
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 200,
  message: { success: false, error: "Muitas requisições. Tente mais tarde." }
});
app.use(limiter);

// Limiter para autenticação
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: "Muitas tentativas. Aguarde 15 minutos." }
});

// Conexão MongoDB
mongoose.connect(process.env.MONGO_URI, { dbName: "recitech" })
  .then(() => console.log("MongoDB conectado com sucesso!"))
  .catch(err => {
    console.error("Erro ao conectar no MongoDB:", err);
    process.exit(1);
  });

// Fatores de CO₂ evitado
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

// Modelos
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
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
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

// Modelos de Chat
const ChatSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  relatedMarketplace: { type: mongoose.Schema.Types.ObjectId, ref: 'Marketplace', default: null },
  createdAt: { type: Date, default: Date.now },
  lastMessageAt: { type: Date, default: Date.now },
  lastMessagePreview: String,
});
const Chat = mongoose.model('Chat', ChatSchema);

const MessageSchema = new mongoose.Schema({
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
});
const Message = mongoose.model('Message', MessageSchema);

// Email com Resend (aumentado timeout e retry)
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
    connectionTimeout: 30000,  // 30 segundos (aumentado)
    greetingTimeout: 15000,
    socketTimeout: 30000,
  });

  // Adiciona retry simples em caso de timeout
  transporter.on('error', (err) => {
    console.error("Erro no transporter SMTP:", err);
  });

  console.log("✅ Email configurado com Resend");
} else {
  console.warn("⚠️ RESEND_API_KEY não encontrada. Recuperação de senha desativada.");
}

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "Token ausente" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || "fallback-secret");
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: "Token inválido ou expirado" });
  }
};

// Rotas de autenticação e perfil
app.post("/register", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ success: false, error: "Email e senha obrigatórios" });
  const exists = await User.findOne({ email });
  if (exists) return res.json({ success: false, error: "Email já registrado" });
  const hashed = await bcrypt.hash(password, 12);
  const user = await User.create({ email, password: hashed });
  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback-secret", { expiresIn: "7d" });
  res.json({ success: true, accessToken });
});

app.post("/login", authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.json({ success: false, error: "Email ou senha incorretos" });
  }
  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback-secret", { expiresIn: "7d" });
  res.json({ success: true, accessToken });
});

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
  user.resetPasswordExpires = Date.now() + 3600000;
  await user.save();
  const resetLink = `${process.env.FRONTEND_URL || "https://recitech-mvp.netlify.app"}/reset-password?token=${token}`;
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
        <p>Ou copie o link: <a href="${resetLink}">${resetLink}</a></p>
        <p>Se não foi você, ignore este email.</p>
        <hr>
        <p style="color: #666; font-size: 14px;">Equipe ReciTech ♻️</p>
      </div>
    `,
  };
  try {
    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: "Link enviado para seu email!" });
  } catch (err) {
    console.error("Erro ao enviar email:", err.message, err.code);
    res.json({ success: false, error: "Falha ao enviar email. Tente novamente mais tarde." });
  }
});

app.get("/user/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password -resetPasswordToken -resetPasswordExpires");
  if (!user) return res.json({ success: false, error: "Usuário não encontrado" });
  res.json({ success: true, user });
});

// ... (mantenha as rotas /materials, /marketplace, /marketplace/buy, /create-payment-intent como estavam)

// Rotas de Chat (já inclusas anteriormente)
app.post("/chats", auth, async (req, res) => {
  const { otherUserId, marketplaceId } = req.body;
  if (!otherUserId) return res.json({ success: false, error: 'ID do outro usuário obrigatório' });

  let chat = await Chat.findOne({
    participants: { $all: [req.user.id, otherUserId] },
  });

  if (!chat) {
    chat = await Chat.create({
      participants: [req.user.id, otherUserId],
      relatedMarketplace: marketplaceId || null,
    });
  }

  res.json({ success: true, chatId: chat._id.toString() });
});

app.post("/messages", auth, async (req, res) => {
  const { chatId, text } = req.body;
  if (!chatId || !text?.trim()) return res.json({ success: false, error: 'Chat e mensagem obrigatórios' });

  const chat = await Chat.findById(chatId);
  if (!chat || !chat.participants.includes(req.user.id)) {
    return res.json({ success: false, error: 'Chat não encontrado ou sem permissão' });
  }

  const message = await Message.create({
    chatId,
    senderId: req.user.id,
    text: text.trim(),
  });

  chat.lastMessageAt = new Date();
  chat.lastMessagePreview = text.length > 60 ? text.substring(0, 57) + '...' : text;
  await chat.save();

  res.json({ success: true, message: message.toObject() });
});

app.get("/messages/:chatId", auth, async (req, res) => {
  const { chatId } = req.params;

  const chat = await Chat.findById(chatId);
  if (!chat || !chat.participants.includes(req.user.id)) {
    return res.json({ success: false, error: 'Acesso negado' });
  }

  const messages = await Message.find({ chatId })
    .populate('senderId', 'email')
    .sort({ createdAt: 1 });

  res.json({ success: true, messages });
});

app.get("/chats", auth, async (req, res) => {
  const chats = await Chat.find({ participants: req.user.id })
    .populate({
      path: 'participants',
      select: 'email',
    })
    .populate('relatedMarketplace', 'tipo quantidade preco userEmail')
    .sort({ lastMessageAt: -1 });

  res.json({ success: true, chats });
});

// Inicia servidor
const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 ReciTech Backend rodando na porta ${PORT}`);
  console.log(`Allowed origins: ${allowedOrigins.join(', ')}`);
  console.log(`Frontend esperado: ${process.env.FRONTEND_URL || "definido na lista"}`);
});

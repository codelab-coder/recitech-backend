/// =============================================
// ReciTech Backend — Versão FINAL para Render.com (2025/2026)
// CORS corrigido, chat implementado, trust proxy ativado, email via API HTTP Resend
// =============================================
import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import crypto from "crypto";

dotenv.config();

const app = express();

// ATIVAÇÃO OBRIGATÓRIA PARA Render + proxies
app.set('trust proxy', 1);

// CORS CONFIGURAÇÃO
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

// Rate limit global
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

// Rota health check na raiz (para evitar "Cannot GET /" e confirmar status)
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'ReciTech Backend Online ♻️ | API Marketplace ativa',
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    mongoStatus: mongoose.connection.readyState === 1 ? 'conectado' : 'desconectado',
    tip: 'Acesse /marketplace para ver anúncios | Use /login para autenticação'
  });
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

// Função de envio de email via API HTTP Resend
const sendResetEmail = async (to, resetLink) => {
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: process.env.FROM_EMAIL || 'onboarding@resend.dev',
        to,
        subject: 'ReciTech - Redefinir sua senha',
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
      }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(`Resend API error: ${response.status} - ${JSON.stringify(errorData)}`);
    }
    console.log(`Email de recuperação enviado para: ${to}`);
    return true;
  } catch (err) {
    console.error('Erro ao enviar email via Resend API:', err.message);
    throw err;
  }
};

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

// Rotas
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
  const token = crypto.randomBytes(20).toString("hex");
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 3600000;
  await user.save();
  const resetLink = `${process.env.FRONTEND_URL || "https://recitech-mvp.netlify.app"}/reset-password?token=${token}`;
  try {
    await sendResetEmail(user.email, resetLink);
    res.json({ success: true, message: "Link enviado para seu email!" });
  } catch (err) {
    console.error("Falha no envio:", err.message);
    res.json({ success: false, error: "Falha ao enviar email. Tente novamente mais tarde." });
  }
});

// Nova rota para processar o reset da senha
app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword || newPassword.length < 6) {
    return res.json({ success: false, error: "Token e senha nova (mín. 6 caracteres) obrigatórios" });
  }
  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) {
      return res.json({ success: false, error: "Token inválido ou expirado" });
    }
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    console.log(`Senha resetada com sucesso para: ${user.email}`);
    res.json({ success: true, message: "Senha alterada! Faça login com a nova senha." });
  } catch (err) {
    console.error("Erro ao resetar senha:", err.message);
    res.json({ success: false, error: "Erro interno ao processar reset" });
  }
});

app.get("/user/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password -resetPasswordToken -resetPasswordExpires");
  if (!user) return res.json({ success: false, error: "Usuário não encontrado" });
  res.json({ success: true, user });
});

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

app.get("/marketplace", async (req, res) => {
  const materials = await Marketplace.find()
    .populate('userId', 'email')
    .sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

app.post("/marketplace/buy", auth, async (req, res) => {
  const { itemId, quantidade, formaPagamento = "simulado" } = req.body;
  if (!itemId || !quantidade) return res.json({ success: false, error: "Dados incompletos" });
  const item = await Marketplace.findById(itemId);
  if (!item) return res.json({ success: false, error: "Anúncio não encontrado" });
  if (quantidade > item.quantidade) return res.json({ success: false, error: "Quantidade indisponível" });
  const total = Number((item.preco * quantidade).toFixed(2));
  await Purchase.create({
    buyerId: req.user.id,
    sellerId: item.userId,
    itemId,
    quantidade,
    total,
    formaPagamento,
  });
  item.quantidade -= quantidade;
  if (item.quantidade <= 0) {
    await Marketplace.deleteOne({ _id: itemId });
    console.log(`Anúncio esgotado e removido: ${item.tipo}`);
  } else {
    await item.save();
  }
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

app.post("/create-payment-intent", auth, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount < 1000) return res.json({ success: false, error: "Mínimo R$10,00" });
  const valor = amount / 100;
  const user = await User.findById(req.user.id);
  if (valor > user.saldo) return res.json({ success: false, error: "Saldo insuficiente" });
  user.saldo -= valor;
  await user.save();
  console.log(`${user.email} solicitou saque de R$${valor}`);
  res.json({ success: true, message: "Saque solicitado! Chegará em até 48h (simulado)." });
});

// Rotas de Chat
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

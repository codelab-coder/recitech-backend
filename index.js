// =============================================
// ReciTech Backend v2 — Sincronizado com Frontend v2
// Novas funcionalidades: perfil profissional, verificação, reputação,
// denúncias, negociações com status, dashboard ESG, busca avançada,
// geolocalização, paginação, tipos de usuário no cadastro.
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
app.set("trust proxy", 1);

// ─── CORS ──────────────────────────────────────────────────────────────────────

const allowedOrigins = [
  "https://recitech-mvp.netlify.app",
  "https://recitechmvp.netlify.app",
  "http://localhost:19006",
  "http://localhost:19000",
  "http://localhost:3000",
  "http://localhost:8081",
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    console.warn(`[CORS] Bloqueado: ${origin}`);
    callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"],
  optionsSuccessStatus: 200,
}));

app.use((req, res, next) => {
  if (req.method === "OPTIONS") console.log(`[OPTIONS] Origin: ${req.headers.origin || "sem origin"}`);
  next();
});

app.use(express.json({ limit: "15mb" }));
app.use(helmet({ contentSecurityPolicy: false }));

// ─── RATE LIMITS ───────────────────────────────────────────────────────────────

const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 300,
  message: { success: false, error: "Muitas requisições. Tente mais tarde." },
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 15,
  message: { success: false, error: "Muitas tentativas. Aguarde 15 minutos." },
});

// ─── HEALTH CHECK ──────────────────────────────────────────────────────────────

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "ReciTech Backend v2 Online ♻️",
    status: "healthy",
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    mongoStatus: mongoose.connection.readyState === 1 ? "conectado" : "desconectado",
  });
});

// ─── MONGODB ───────────────────────────────────────────────────────────────────

mongoose.connect(process.env.MONGO_URI, { dbName: "recitech" })
  .then(() => console.log("MongoDB conectado!"))
  .catch((err) => { console.error("Erro MongoDB:", err); process.exit(1); });

// ─── CONSTANTES ────────────────────────────────────────────────────────────────

const CO2_POR_KG = {
  plástico: 2.0, pet: 2.5, papel: 1.2, papelão: 1.0,
  metal: 4.0, alumínio: 10.0, vidro: 0.35, orgânico: 0.5,
  eletrônico: 8.0, bateria: 12.0, óleo: 3.0, borracha: 2.2,
  madeira: 1.1, têxtil: 3.5, desconhecido: 1.5,
};

const TAXA_PLATAFORMA = 0.03; // 3%

// ─── SCHEMAS / MODELS ──────────────────────────────────────────────────────────

// User — expandido com todos os campos do frontend v2
const UserSchema = new mongoose.Schema({
  email:    { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: String,

  // Tipo de cadastro (novo no v2)
  tipoUsuario: { type: String, enum: ["pessoa_fisica", "condominio", "cooperativa", "empresa"], default: "pessoa_fisica" },
  nomeCompleto: String,   // pessoa física
  nomeOrg:      String,   // nome da org (condomínio/cooperativa/empresa)

  // Perfil profissional
  nomeEmpresa:        String,
  descricao:          String,
  horarioAtendimento: String,
  areaAtuacao:        String,
  cidade:             String,
  fotoPerfil:         String,

  // Verificação de identidade
  cpf:               String,
  cnpj:              String,
  telefone:          String,
  verificado:        { type: Boolean, default: false },
  empresaVerificada: { type: Boolean, default: false },

  // Reputação
  notaMedia:        { type: Number, default: 0 },
  totalAvaliacoes:  { type: Number, default: 0 },
  totalNegociacoes: { type: Number, default: 0 },

  // ESG / métricas
  saldo:            { type: Number, default: 0 },
  kgTotal:          { type: Number, default: 0 },  // alias para totalKg (usado no frontend)
  totalKg:          { type: Number, default: 0 },
  totalCo2:         { type: Number, default: 0 },
  rank:             { type: String, default: "Bronze" },
  historicoMensal:  { type: [Number], default: [0, 0, 0, 0, 0, 0] },

  // Reset de senha
  resetPasswordToken:   String,
  resetPasswordExpires: Date,
  criadoEm: { type: Date, default: Date.now },
});
const User = mongoose.model("User", UserSchema);

// Material (scan IA — mantido do v1)
const MaterialSchema = new mongoose.Schema({
  userId:      String,
  type:        String,
  estimatedKg: Number,
  value:       Number,
  photoBase64: String,
  createdAt:   { type: Date, default: Date.now },
});
const Material = mongoose.model("Material", MaterialSchema);

// Marketplace — expandido com localização e campos de reputação do vendedor
const MarketplaceSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  userEmail: String,
  tipo:      String,
  quantidade: Number,
  preco:     Number,
  telefone:  String,
  cidade:    String,
  descricao: String,
  fotoBase64: String,

  // Geolocalização (novo v2)
  latitude:  Number,
  longitude: Number,

  // Cache de reputação do vendedor (novo v2 — atualizado a cada compra/avaliação)
  vendedorNome:             String,
  vendedorVerificado:       { type: Boolean, default: false },
  vendedorEmpresaVerificada:{ type: Boolean, default: false },
  vendedorNota:             { type: Number, default: 0 },
  vendedorNegociacoes:      { type: Number, default: 0 },
  vendedorKgTotal:          { type: Number, default: 0 },

  patrocinado: { type: Boolean, default: false },
  createdAt:   { type: Date, default: Date.now },
});
const Marketplace = mongoose.model("Marketplace", MarketplaceSchema);

// Negociação — substitui Purchase, com status timeline (novo v2)
const NegociacaoSchema = new mongoose.Schema({
  compradorId:    { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  compradorEmail: String,
  vendedorId:     { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  vendedorEmail:  String,
  marketplaceId:  { type: mongoose.Schema.Types.ObjectId, ref: "Marketplace" },
  tipo:           String,
  quantidade:     Number,
  preco:          Number,
  valorTotal:     Number,
  taxaPlataforma: Number,
  formaPagamento: String,

  // Status timeline (novo v2)
  status: {
    type: String,
    enum: ["aguardando_pagamento", "pagamento_aprovado", "em_coleta", "em_transporte", "finalizado", "cancelado"],
    default: "aguardando_pagamento",
  },

  // Escrow (novo v2)
  escrow:          { type: Boolean, default: false },
  escrowLiberado:  { type: Boolean, default: false },

  avaliado: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
const Negociacao = mongoose.model("Negociacao", NegociacaoSchema);

// Avaliação (novo v2)
const AvaliacaoSchema = new mongoose.Schema({
  negociacaoId: { type: mongoose.Schema.Types.ObjectId, ref: "Negociacao" },
  vendedorId:   { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  autorId:      { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  autorEmail:   String,
  nota:         { type: Number, min: 1, max: 5 },
  comentario:   String,
  criadoEm:     { type: Date, default: Date.now },
});
const Avaliacao = mongoose.model("Avaliacao", AvaliacaoSchema);

// Denúncia (novo v2)
const DenunciaSchema = new mongoose.Schema({
  autorId:  { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  tipo:     { type: String, enum: ["usuario", "anuncio"] },
  alvoId:   String,
  motivo:   String,
  detalhe:  String,
  resolvida:{ type: Boolean, default: false },
  criadoEm: { type: Date, default: Date.now },
});
const Denuncia = mongoose.model("Denuncia", DenunciaSchema);

// Chat / Mensagem (mantidos do v1, pequenos ajustes)
const ChatSchema = new mongoose.Schema({
  participants:       [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  relatedMarketplace: { type: mongoose.Schema.Types.ObjectId, ref: "Marketplace", default: null },
  lastMessageAt:      { type: Date, default: Date.now },
  lastMessagePreview: String,
  createdAt:          { type: Date, default: Date.now },
});
const Chat = mongoose.model("Chat", ChatSchema);

const MessageSchema = new mongoose.Schema({
  chatId:    { type: mongoose.Schema.Types.ObjectId, ref: "Chat", required: true },
  senderId:  { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text:      { type: String, required: true },
  read:      { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Message = mongoose.model("Message", MessageSchema);

// ─── HELPERS ───────────────────────────────────────────────────────────────────

// Calcula badge ESG pelo total de kg negociado
const getBadgeESG = (kg = 0) => {
  if (kg >= 2000) return "lenda";
  if (kg >= 1000) return "campeao";
  if (kg >=  500) return "top";
  if (kg >=  100) return "ativo";
  return "iniciante";
};

// Recalcula a nota média de um vendedor e atualiza
const recalcularNotaVendedor = async (vendedorId) => {
  const avaliacoes = await Avaliacao.find({ vendedorId });
  if (!avaliacoes.length) return;
  const media = avaliacoes.reduce((s, a) => s + a.nota, 0) / avaliacoes.length;
  await User.findByIdAndUpdate(vendedorId, {
    notaMedia: Math.round(media * 10) / 10,
    totalAvaliacoes: avaliacoes.length,
  });
  // Atualiza cache nos anúncios ativos do vendedor
  await Marketplace.updateMany(
    { userId: vendedorId },
    { vendedorNota: Math.round(media * 10) / 10 }
  );
};

// Distância Haversine em km
const haversine = (lat1, lon1, lat2, lon2) => {
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) * Math.cos((lat2 * Math.PI) / 180) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
};

// Envio de email via Resend
const sendResetEmail = async (to, resetLink) => {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: process.env.FROM_EMAIL || "onboarding@resend.dev",
      to,
      subject: "ReciTech - Redefinir sua senha",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:20px;border:1px solid #ddd;border-radius:10px;">
          <h2 style="color:#00C853;">Olá!</h2>
          <p>Clique abaixo para redefinir sua senha (válido por 1 hora):</p>
          <div style="text-align:center;margin:30px 0;">
            <a href="${resetLink}" style="background:#00C853;color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px;">
              Redefinir senha
            </a>
          </div>
          <p>Link: <a href="${resetLink}">${resetLink}</a></p>
          <p>Se não foi você, ignore este email.</p>
          <hr><p style="color:#666;font-size:14px;">Equipe ReciTech ♻️</p>
        </div>`,
    }),
  });
  if (!response.ok) {
    const err = await response.json();
    throw new Error(`Resend error: ${response.status} - ${JSON.stringify(err)}`);
  }
  console.log(`Email enviado para: ${to}`);
};

// ─── AUTH MIDDLEWARE ────────────────────────────────────────────────────────────

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "Token ausente" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || "fallback-secret");
    next();
  } catch {
    return res.status(401).json({ success: false, error: "Token inválido ou expirado" });
  }
};

// ─── ROTAS: AUTH ───────────────────────────────────────────────────────────────

// REGISTRO — agora aceita todos os campos do formulário v2
app.post("/register", authLimiter, async (req, res) => {
  try {
    const {
      email, password,
      tipoUsuario, nomeCompleto, nomeOrg,
      documento, telefone, cidade,
    } = req.body;

    if (!email || !password) return res.json({ success: false, error: "Email e senha obrigatórios" });
    if (password.length < 6)  return res.json({ success: false, error: "Senha muito curta (mín. 6 caracteres)" });

    const exists = await User.findOne({ email: email.toLowerCase().trim() });
    if (exists) return res.json({ success: false, error: "Email já registrado" });

    const hashed = await bcrypt.hash(password, 12);

    // Determina se CPF/CNPJ foi informado e gera badge de verificação automático
    const ehPessoaFisica  = tipoUsuario === "pessoa_fisica";
    const documentoLimpo  = (documento || "").replace(/\D/g, "");
    const cpfValido       = ehPessoaFisica  && documentoLimpo.length === 11;
    const cnpjValido      = !ehPessoaFisica && documentoLimpo.length === 14;
    const verificado      = cpfValido;
    const empresaVerificada = cnpjValido;

    // Nome de exibição: empresa/org ou pessoa
    const nomeEmpresa = ehPessoaFisica ? (nomeCompleto || "") : (nomeOrg || "");

    const user = await User.create({
      email: email.toLowerCase().trim(),
      password: hashed,
      tipoUsuario:      tipoUsuario      || "pessoa_fisica",
      nomeCompleto:     nomeCompleto     || "",
      nomeOrg:          nomeOrg          || "",
      nomeEmpresa,
      cpf:              ehPessoaFisica  ? documentoLimpo : "",
      cnpj:             !ehPessoaFisica ? documentoLimpo : "",
      telefone:         (telefone || "").replace(/\D/g, ""),
      cidade:           cidade || "",
      verificado,
      empresaVerificada,
    });

    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback-secret", { expiresIn: "7d" });
    console.log(`[REGISTER] ${user.email} | tipo: ${tipoUsuario} | verificado: ${verificado || empresaVerificada}`);
    res.json({ success: true, accessToken });
  } catch (err) {
    console.error("[REGISTER ERROR]", err.message);
    res.json({ success: false, error: "Erro interno no servidor" });
  }
});

app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email?.toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.json({ success: false, error: "Email ou senha incorretos" });
    }
    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback-secret", { expiresIn: "7d" });
    res.json({ success: true, accessToken });
  } catch (err) {
    console.error("[LOGIN ERROR]", err.message);
    res.json({ success: false, error: "Erro interno" });
  }
});

app.post("/forgot-password", authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ success: false, error: "Email obrigatório" });
  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user) return res.json({ success: true, message: "Se o email existir, enviamos um link." });

  const token = crypto.randomBytes(20).toString("hex");
  user.resetPasswordToken   = token;
  user.resetPasswordExpires = Date.now() + 3600000;
  await user.save();

  const resetLink = `${process.env.FRONTEND_URL || "https://recitech-mvp.netlify.app"}/reset-password?token=${token}`;
  try {
    await sendResetEmail(user.email, resetLink);
    res.json({ success: true, message: "Link enviado para seu email!" });
  } catch (err) {
    console.error("Falha no envio:", err.message);
    res.json({ success: false, error: "Falha ao enviar email." });
  }
});

app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword || newPassword.length < 6) {
    return res.json({ success: false, error: "Token e senha nova (mín. 6 chars) obrigatórios" });
  }
  const user = await User.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: { $gt: Date.now() },
  });
  if (!user) return res.json({ success: false, error: "Token inválido ou expirado" });
  user.password             = await bcrypt.hash(newPassword, 12);
  user.resetPasswordToken   = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();
  res.json({ success: true, message: "Senha alterada! Faça login." });
});

// ─── ROTAS: PERFIL ─────────────────────────────────────────────────────────────

// GET perfil do usuário logado
app.get("/user/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password -resetPasswordToken -resetPasswordExpires");
    if (!user) return res.json({ success: false, error: "Usuário não encontrado" });
    // Garante que kgTotal e totalKg estejam sincronizados
    const userObj = user.toObject();
    userObj.kgTotal = user.kgTotal || user.totalKg || 0;
    res.json({ success: true, user: userObj });
  } catch (err) {
    res.json({ success: false, error: "Erro ao buscar perfil" });
  }
});

// PUT editar perfil profissional
app.put("/user/profile", auth, async (req, res) => {
  try {
    const {
      nomeEmpresa, descricao, horarioAtendimento, areaAtuacao,
      cidade, fotoPerfil, cpf, cnpj, telefone,
    } = req.body;

    const updates = {};
    if (nomeEmpresa         !== undefined) updates.nomeEmpresa         = nomeEmpresa;
    if (descricao           !== undefined) updates.descricao           = descricao?.substring(0, 300);
    if (horarioAtendimento  !== undefined) updates.horarioAtendimento  = horarioAtendimento;
    if (areaAtuacao         !== undefined) updates.areaAtuacao         = areaAtuacao;
    if (cidade              !== undefined) updates.cidade              = cidade;
    if (fotoPerfil          !== undefined) updates.fotoPerfil          = fotoPerfil;
    if (telefone            !== undefined) updates.telefone            = telefone?.replace(/\D/g, "");

    // Verificação de identidade
    if (cpf && cpf.replace(/\D/g, "").length === 11) {
      updates.cpf        = cpf.replace(/\D/g, "");
      updates.verificado = true;
    }
    if (cnpj && cnpj.replace(/\D/g, "").length === 14) {
      updates.cnpj               = cnpj.replace(/\D/g, "");
      updates.empresaVerificada  = true;
    }

    const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true })
      .select("-password -resetPasswordToken -resetPasswordExpires");

    // Propaga verificação nos anúncios ativos
    await Marketplace.updateMany({ userId: req.user.id }, {
      vendedorNome:              user.nomeEmpresa || user.nomeCompleto || user.email,
      vendedorVerificado:        user.verificado,
      vendedorEmpresaVerificada: user.empresaVerificada,
    });

    res.json({ success: true, user });
  } catch (err) {
    console.error("[PUT PROFILE]", err.message);
    res.json({ success: false, error: "Erro ao salvar perfil" });
  }
});

// GET perfil público de qualquer usuário
app.get("/user/:id/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select("-password -resetPasswordToken -resetPasswordExpires -cpf -cnpj");
    if (!user) return res.json({ success: false, error: "Usuário não encontrado" });
    const userObj = user.toObject();
    userObj.kgTotal = user.kgTotal || user.totalKg || 0;
    res.json({ success: true, user: userObj });
  } catch {
    res.json({ success: false, error: "Erro ao buscar perfil" });
  }
});

// GET avaliações de um usuário
app.get("/user/:id/reviews", auth, async (req, res) => {
  try {
    const reviews = await Avaliacao.find({ vendedorId: req.params.id })
      .sort({ criadoEm: -1 })
      .limit(20);
    res.json({ success: true, reviews });
  } catch {
    res.json({ success: false, error: "Erro ao buscar avaliações" });
  }
});

// ─── ROTAS: MARKETPLACE ────────────────────────────────────────────────────────

// POST criar anúncio — agora inclui lat/lon e propaga dados do vendedor
app.post("/marketplace", auth, async (req, res) => {
  try {
    const { tipo, quantidade, preco, telefone, cidade, descricao, fotoBase64, latitude, longitude } = req.body;

    if (!tipo || !quantidade || !preco) {
      return res.json({ success: false, error: "Tipo, quantidade e preço são obrigatórios" });
    }
    if (Number(quantidade) <= 0 || Number(preco) <= 0) {
      return res.json({ success: false, error: "Quantidade e preço devem ser positivos" });
    }

    const user = await User.findById(req.user.id);

    await Marketplace.create({
      userId:    req.user.id,
      userEmail: user.email,
      tipo,
      quantidade:  Number(quantidade),
      preco:       Number(preco),
      telefone:    telefone?.trim() || null,
      cidade:      cidade?.trim()   || user.cidade || null,
      descricao:   descricao?.trim()?.substring(0, 500) || null,
      fotoBase64,
      latitude:    latitude  || null,
      longitude:   longitude || null,

      // Cache do vendedor
      vendedorNome:              user.nomeEmpresa || user.nomeCompleto || user.email,
      vendedorVerificado:        user.verificado        || false,
      vendedorEmpresaVerificada: user.empresaVerificada || false,
      vendedorNota:              user.notaMedia          || 0,
      vendedorNegociacoes:       user.totalNegociacoes   || 0,
      vendedorKgTotal:           user.kgTotal || user.totalKg || 0,
    });

    console.log(`[ANUNCIO] ${user.email} publicou ${quantidade}kg de ${tipo} a R$${preco}/kg`);
    res.json({ success: true });
  } catch (err) {
    console.error("[POST MARKETPLACE]", err.message);
    res.json({ success: false, error: "Erro ao publicar anúncio" });
  }
});

// GET marketplace — com paginação, filtros, busca e geolocalização
app.get("/marketplace", async (req, res) => {
  try {
    const {
      page = 1, limit = 10,
      tipo, verificado, precMax, qtdMin, q,
      lat, lon, raio,
    } = req.query;

    const pageNum  = Math.max(1, parseInt(page));
    const limitNum = Math.min(50, Math.max(1, parseInt(limit)));
    const skip     = (pageNum - 1) * limitNum;

    // Monta filtro MongoDB
    const filter = {};
    if (tipo && tipo !== "todos") filter.tipo = tipo;
    if (verificado === "true")    filter.vendedorVerificado = true;
    if (precMax)  filter.preco    = { $lte: parseFloat(precMax) };
    if (qtdMin)   filter.quantidade = { ...filter.quantidade, $gte: parseFloat(qtdMin) };
    if (q) {
      filter.$or = [
        { tipo:           { $regex: q, $options: "i" } },
        { userEmail:      { $regex: q, $options: "i" } },
        { descricao:      { $regex: q, $options: "i" } },
        { vendedorNome:   { $regex: q, $options: "i" } },
        { cidade:         { $regex: q, $options: "i" } },
      ];
    }

    let materials = await Marketplace.find(filter)
      .sort({ patrocinado: -1, createdAt: -1 })
      .skip(skip)
      .limit(limitNum * 3) // busca extra para filtrar por distância depois
      .lean();

    // Filtro por distância (geolocalização) — feito em memória após query
    if (lat && lon && raio) {
      const latN = parseFloat(lat);
      const lonN = parseFloat(lon);
      const raioN = parseFloat(raio);
      materials = materials.filter((m) => {
        if (!m.latitude || !m.longitude) return true; // inclui anúncios sem localização
        return haversine(latN, lonN, m.latitude, m.longitude) <= raioN;
      });
    }

    // Limita ao tamanho correto após filtro de distância
    const total    = materials.length;
    const paginated = materials.slice(0, limitNum);

    res.json({ success: true, materials: paginated, total, page: pageNum, limit: limitNum });
  } catch (err) {
    console.error("[GET MARKETPLACE]", err.message);
    res.json({ success: false, error: "Erro ao buscar anúncios" });
  }
});

// ─── ROTAS: COMPRA / NEGOCIAÇÃO ────────────────────────────────────────────────

// POST comprar item — cria Negociacao, substitui Purchase
app.post("/marketplace/buy", auth, async (req, res) => {
  try {
    const { itemId, quantidade, formaPagamento = "simulado" } = req.body;
    if (!itemId || !quantidade) return res.json({ success: false, error: "Dados incompletos" });

    const item = await Marketplace.findById(itemId);
    if (!item) return res.json({ success: false, error: "Anúncio não encontrado" });
    if (String(item.userId) === String(req.user.id)) return res.json({ success: false, error: "Você não pode comprar seu próprio anúncio" });
    if (Number(quantidade) > item.quantidade) return res.json({ success: false, error: "Quantidade indisponível" });

    const total         = Number((item.preco * quantidade).toFixed(2));
    const taxa          = Number((total * TAXA_PLATAFORMA).toFixed(2));
    const valorLiquido  = Number((total - taxa).toFixed(2));
    const ehEscrow      = formaPagamento === "escrow";

    const vendedor = await User.findById(item.userId);
    const comprador = await User.findById(req.user.id);

    // Cria negociação
    const negociacao = await Negociacao.create({
      compradorId:    req.user.id,
      compradorEmail: comprador.email,
      vendedorId:     item.userId,
      vendedorEmail:  vendedor.email,
      marketplaceId:  itemId,
      tipo:           item.tipo,
      quantidade:     Number(quantidade),
      preco:          item.preco,
      valorTotal:     total,
      taxaPlataforma: taxa,
      formaPagamento,
      status:         "aguardando_pagamento",
      escrow:         ehEscrow,
    });

    // Atualiza estoque
    item.quantidade -= Number(quantidade);
    if (item.quantidade <= 0) {
      await Marketplace.deleteOne({ _id: itemId });
    } else {
      await item.save();
    }

    // Escrow: segura o valor (não repassa ainda)
    // Pagamento normal/simulado: repassa imediatamente
    if (!ehEscrow) {
      vendedor.saldo  += valorLiquido;
      vendedor.kgTotal = (vendedor.kgTotal || 0) + Number(quantidade);
      vendedor.totalKg = vendedor.kgTotal;
      vendedor.totalNegociacoes = (vendedor.totalNegociacoes || 0) + 1;
      await vendedor.save();
      negociacao.status          = "pagamento_aprovado";
      negociacao.escrowLiberado  = true;
      await negociacao.save();
    }

    // Atualiza badge ESG do vendedor nos anúncios
    await Marketplace.updateMany({ userId: item.userId }, {
      vendedorKgTotal:     vendedor.kgTotal,
      vendedorNegociacoes: vendedor.totalNegociacoes,
    });

    const msg =
      formaPagamento === "pix"    ? `PIX gerado: R$ ${total.toFixed(2)}` :
      formaPagamento === "escrow" ? "Pagamento em escrow! Aguardando confirmação de entrega." :
      "Compra realizada com sucesso!";

    console.log(`[COMPRA] ${comprador.email} comprou ${quantidade}kg de ${item.tipo} de ${vendedor.email} | R$${total} | ${formaPagamento}`);
    res.json({ success: true, valor: total, message: msg, negociacaoId: negociacao._id });
  } catch (err) {
    console.error("[BUY ERROR]", err.message);
    res.json({ success: false, error: "Erro ao processar compra" });
  }
});

// ─── ROTAS: NEGOCIAÇÕES ────────────────────────────────────────────────────────

// GET listar negociações do usuário (comprador ou vendedor)
app.get("/negociacoes", auth, async (req, res) => {
  try {
    const negociacoes = await Negociacao.find({
      $or: [{ compradorId: req.user.id }, { vendedorId: req.user.id }],
    }).sort({ createdAt: -1 }).lean();

    res.json({ success: true, negociacoes });
  } catch (err) {
    res.json({ success: false, error: "Erro ao buscar negociações" });
  }
});

// PUT atualizar status de uma negociação (somente vendedor)
app.put("/negociacoes/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const statusValidos = ["pagamento_aprovado", "em_coleta", "em_transporte", "finalizado", "cancelado"];

    if (!statusValidos.includes(status)) {
      return res.json({ success: false, error: "Status inválido" });
    }

    const negociacao = await Negociacao.findById(req.params.id);
    if (!negociacao) return res.json({ success: false, error: "Negociação não encontrada" });

    // Somente o vendedor pode atualizar o status (exceto cancelar — ambos podem)
    if (String(negociacao.vendedorId) !== String(req.user.id) && status !== "cancelado") {
      return res.json({ success: false, error: "Sem permissão para alterar este status" });
    }

    negociacao.status    = status;
    negociacao.updatedAt = new Date();

    // Ao finalizar: libera escrow se houver
    if (status === "finalizado" && negociacao.escrow && !negociacao.escrowLiberado) {
      const vendedor    = await User.findById(negociacao.vendedorId);
      const valorLiquido = Number((negociacao.valorTotal - negociacao.taxaPlataforma).toFixed(2));
      vendedor.saldo   += valorLiquido;
      vendedor.kgTotal  = (vendedor.kgTotal || 0) + negociacao.quantidade;
      vendedor.totalKg  = vendedor.kgTotal;
      vendedor.totalNegociacoes = (vendedor.totalNegociacoes || 0) + 1;
      await vendedor.save();
      negociacao.escrowLiberado = true;
      await Marketplace.updateMany({ userId: negociacao.vendedorId }, {
        vendedorKgTotal: vendedor.kgTotal,
        vendedorNegociacoes: vendedor.totalNegociacoes,
      });
      console.log(`[ESCROW] Liberado R$${valorLiquido} para ${vendedor.email}`);
    }

    await negociacao.save();
    console.log(`[STATUS] Negociação ${negociacao._id} → ${status}`);
    res.json({ success: true, negociacao });
  } catch (err) {
    console.error("[STATUS ERROR]", err.message);
    res.json({ success: false, error: "Erro ao atualizar status" });
  }
});

// ─── ROTAS: AVALIAÇÕES ─────────────────────────────────────────────────────────

// POST criar avaliação pós-negociação
app.post("/avaliacoes", auth, async (req, res) => {
  try {
    const { negociacaoId, vendedorId, nota, comentario } = req.body;

    if (!nota || nota < 1 || nota > 5) return res.json({ success: false, error: "Nota entre 1 e 5" });
    if (!comentario?.trim())           return res.json({ success: false, error: "Comentário obrigatório" });

    // Verifica se a negociação existe e pertence ao comprador
    const negociacao = await Negociacao.findById(negociacaoId);
    if (!negociacao || String(negociacao.compradorId) !== String(req.user.id)) {
      return res.json({ success: false, error: "Negociação não encontrada" });
    }
    if (negociacao.avaliado) return res.json({ success: false, error: "Negociação já avaliada" });
    if (negociacao.status !== "finalizado") return res.json({ success: false, error: "Só é possível avaliar após a entrega" });

    const autor = await User.findById(req.user.id);

    await Avaliacao.create({
      negociacaoId,
      vendedorId,
      autorId:    req.user.id,
      autorEmail: autor.email,
      nota:       Number(nota),
      comentario: comentario.trim().substring(0, 400),
    });

    negociacao.avaliado = true;
    await negociacao.save();

    // Recalcula nota média do vendedor
    await recalcularNotaVendedor(vendedorId);

    console.log(`[AVALIACAO] ${autor.email} avaliou negociação ${negociacaoId} com nota ${nota}`);
    res.json({ success: true });
  } catch (err) {
    console.error("[AVALIACAO ERROR]", err.message);
    res.json({ success: false, error: "Erro ao criar avaliação" });
  }
});

// ─── ROTAS: DENÚNCIAS ──────────────────────────────────────────────────────────

// POST criar denúncia
app.post("/denuncias", auth, async (req, res) => {
  try {
    const { tipo, alvoId, motivo, detalhe } = req.body;
    if (!tipo || !alvoId || !motivo) return res.json({ success: false, error: "Dados incompletos" });
    if (!["usuario", "anuncio"].includes(tipo)) return res.json({ success: false, error: "Tipo inválido" });

    await Denuncia.create({
      autorId: req.user.id,
      tipo, alvoId, motivo,
      detalhe: detalhe?.substring(0, 500) || "",
    });

    const autor = await User.findById(req.user.id);
    console.log(`[DENUNCIA] ${autor.email} denunciou ${tipo} id:${alvoId} | motivo: ${motivo}`);
    res.json({ success: true });
  } catch (err) {
    console.error("[DENUNCIA ERROR]", err.message);
    res.json({ success: false, error: "Erro ao enviar denúncia" });
  }
});

// ─── ROTAS: CHAT / MENSAGENS ───────────────────────────────────────────────────

// POST criar ou encontrar chat existente
app.post("/chats", auth, async (req, res) => {
  try {
    const { otherUserId, marketplaceId } = req.body;
    if (!otherUserId) return res.json({ success: false, error: "ID do usuário obrigatório" });
    if (otherUserId === String(req.user.id)) return res.json({ success: false, error: "Você não pode conversar com você mesmo" });

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
  } catch (err) {
    res.json({ success: false, error: "Erro ao criar chat" });
  }
});

// GET listar chats do usuário — com contador de não lidas
app.get("/chats", auth, async (req, res) => {
  try {
    const chats = await Chat.find({ participants: req.user.id })
      .populate({ path: "participants", select: "email nomeEmpresa nomeCompleto fotoPerfil verificado empresaVerificada tipoUsuario" })
      .populate("relatedMarketplace", "tipo quantidade preco userEmail")
      .sort({ lastMessageAt: -1 })
      .lean();

    // Conta mensagens não lidas por chat
    const chatsComNaoLidas = await Promise.all(
      chats.map(async (chat) => {
        const naoLidas = await Message.countDocuments({
          chatId: chat._id,
          senderId: { $ne: req.user.id },
          read: false,
        });
        return { ...chat, naoLidas };
      })
    );

    res.json({ success: true, chats: chatsComNaoLidas });
  } catch (err) {
    console.error("[GET CHATS]", err.message);
    res.json({ success: false, error: "Erro ao buscar conversas" });
  }
});

// GET mensagens de um chat — com paginação
app.get("/messages/:chatId", auth, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const pageNum  = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const skip     = (pageNum - 1) * limitNum;

    const chat = await Chat.findById(req.params.chatId);
    if (!chat || !chat.participants.map(String).includes(String(req.user.id))) {
      return res.json({ success: false, error: "Acesso negado" });
    }

    const messages = await Message.find({ chatId: req.params.chatId })
      .populate("senderId", "email nomeEmpresa")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    // Marca como lidas as mensagens do outro
    await Message.updateMany(
      { chatId: req.params.chatId, senderId: { $ne: req.user.id }, read: false },
      { read: true }
    );

    res.json({ success: true, messages: messages.reverse() });
  } catch (err) {
    console.error("[GET MESSAGES]", err.message);
    res.json({ success: false, error: "Erro ao buscar mensagens" });
  }
});

// POST enviar mensagem
app.post("/messages", auth, async (req, res) => {
  try {
    const { chatId, text } = req.body;
    if (!chatId || !text?.trim()) return res.json({ success: false, error: "Chat e mensagem obrigatórios" });
    if (text.length > 1000)       return res.json({ success: false, error: "Mensagem muito longa (máx 1000 chars)" });

    const chat = await Chat.findById(chatId);
    if (!chat || !chat.participants.map(String).includes(String(req.user.id))) {
      return res.json({ success: false, error: "Chat não encontrado ou sem permissão" });
    }

    const message = await Message.create({
      chatId,
      senderId: req.user.id,
      text:     text.trim(),
    });

    chat.lastMessageAt      = new Date();
    chat.lastMessagePreview = text.length > 60 ? text.substring(0, 57) + "..." : text;
    await chat.save();

    const populated = await message.populate("senderId", "email nomeEmpresa");
    res.json({ success: true, message: populated.toObject() });
  } catch (err) {
    console.error("[POST MESSAGE]", err.message);
    res.json({ success: false, error: "Erro ao enviar mensagem" });
  }
});

// ─── ROTAS: ESG DASHBOARD ──────────────────────────────────────────────────────

app.get("/esg/dashboard", auth, async (req, res) => {
  try {
    // Agrega dados de todos os usuários e negociações
    const [usuariosStats, negociacoesStats, materiaisStats] = await Promise.all([
      User.aggregate([
        { $group: {
          _id: null,
          totalKg:       { $sum: { $add: ["$kgTotal", "$totalKg"] } },
          usuariosAtivos: { $sum: { $cond: [{ $gt: ["$totalNegociacoes", 0] }, 1, 0] } },
        }},
      ]),
      Negociacao.aggregate([
        { $match: { status: "finalizado" } },
        { $group: {
          _id: null,
          totalNegociacoes: { $sum: 1 },
          totalKgNeg:       { $sum: "$quantidade" },
        }},
      ]),
      Negociacao.aggregate([
        { $match: { status: "finalizado" } },
        { $group: { _id: "$tipo", totalKg: { $sum: "$quantidade" } } },
      ]),
    ]);

    const totalKg         = (usuariosStats[0]?.totalKg || 0) / 2; // evita dupla contagem
    const co2Evitado      = totalKg * 2.5;
    const usuariosAtivos  = usuariosStats[0]?.usuariosAtivos || 0;
    const negociacoes     = negociacoesStats[0]?.totalNegociacoes || 0;

    // Monta objeto de materiais
    const materiais = {};
    materiaisStats.forEach((m) => {
      if (m._id) materiais[m._id] = m.totalKg;
    });

    res.json({
      success: true,
      dados: { totalKg, co2Evitado, usuariosAtivos, negociacoes, materiais },
    });
  } catch (err) {
    console.error("[ESG DASHBOARD]", err.message);
    res.json({ success: false, error: "Erro ao buscar dados ESG" });
  }
});

// ─── ROTAS: MATERIALS (scan IA — mantido do v1) ────────────────────────────────

app.post("/materials", auth, async (req, res) => {
  try {
    const { photoBase64 } = req.body;
    if (!photoBase64) return res.json({ success: false, error: "Foto obrigatória" });

    const tipos = Object.keys(CO2_POR_KG).filter((t) => t !== "desconhecido");
    const type       = tipos[Math.floor(Math.random() * tipos.length)];
    const estimatedKg = Number((Math.random() * 1.4 + 0.1).toFixed(2));
    const precoPorKg = {
      plástico: 2.8, pet: 3.5, papel: 1.2, papelão: 1.0,
      metal: 4.5, alumínio: 6.8, vidro: 0.8, orgânico: 0.3,
      eletrônico: 15.0, bateria: 20.0, óleo: 5.0,
      borracha: 2.0, madeira: 1.5, têxtil: 1.8,
    }[type] || 1.0;
    const value      = Number((precoPorKg * estimatedKg).toFixed(2));
    const co2Evitado = estimatedKg * (CO2_POR_KG[type] || 1.5);

    await Material.create({ userId: req.user.id, type, estimatedKg, value, photoBase64 });

    const user = await User.findById(req.user.id);
    user.saldo   += value;
    user.kgTotal  = (user.kgTotal || 0) + estimatedKg;
    user.totalKg  = user.kgTotal;
    user.totalCo2 = (user.totalCo2 || 0) + co2Evitado;
    await user.save();

    console.log(`[SCAN] ${user.email} → ${estimatedKg}kg de ${type} | +R$${value}`);
    res.json({ success: true, type, estimatedKg, value });
  } catch (err) {
    res.json({ success: false, error: "Erro ao processar material" });
  }
});

app.get("/materials", auth, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

// ─── ROTA: SAQUE ───────────────────────────────────────────────────────────────

app.post("/create-payment-intent", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount < 1000) return res.json({ success: false, error: "Mínimo R$10,00" });
    const valor = amount / 100;
    const user = await User.findById(req.user.id);
    if (valor > user.saldo) return res.json({ success: false, error: "Saldo insuficiente" });
    user.saldo -= valor;
    await user.save();
    console.log(`[SAQUE] ${user.email} solicitou R$${valor}`);
    res.json({ success: true, message: "Saque solicitado! Chegará em até 48h (simulado)." });
  } catch (err) {
    res.json({ success: false, error: "Erro no saque" });
  }
});

// ─── 404 ───────────────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ success: false, error: `Rota ${req.method} ${req.path} não encontrada` });
});

// ─── START ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 ReciTech Backend v2 rodando na porta ${PORT}`);
  console.log(`Origins permitidos: ${allowedOrigins.join(", ")}`);
});

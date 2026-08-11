/**
 * ReciTech Marketplace — Backend (arquivo único)
 * ------------------------------------------------
 * API REST em Node.js + Express + MongoDB, alinhada aos endpoints consumidos
 * pelo App.js (React Native/Expo) do marketplace de materiais recicláveis.
 *
 * Tudo num arquivo só por simplicidade de deploy (ex.: Render/Railway free tier).
 * Seções (Ctrl+F):
 *   1. Config / env
 *   2. Logger (winston)
 *   3. Conexão MongoDB
 *   4. Utils (geo, asyncHandler, JWT)
 *   5. Models (Mongoose)
 *   6. Validação (Joi schemas)
 *   7. Middlewares (auth, validate, rate limit, error handler)
 *   8. Swagger
 *   9. Rotas / Controllers
 *  10. Boot do servidor
 *
 * Rodar:
 *   cp .env.example .env   (ajuste MONGO_URI e JWT_SECRET)
 *   npm install
 *   npm start   (ou: npm run dev)
 */

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const winston = require("winston");
const Joi = require("joi");
const rateLimit = require("express-rate-limit");
const { cpf, cnpj } = require("cpf-cnpj-validator");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

// ─────────────────────────────────────────────────────────────────────────
// 1. CONFIG / ENV
// ─────────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/recitech";
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_troque_isso";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";
const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS) || 10;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "*";
const RATE_LIMIT_WINDOW_MIN = Number(process.env.RATE_LIMIT_WINDOW_MIN) || 15;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 50;

if (process.env.NODE_ENV !== "test" && JWT_SECRET === "dev_secret_troque_isso") {
  // eslint-disable-next-line no-console
  console.warn("[AVISO] JWT_SECRET não definido no .env — usando valor de desenvolvimento inseguro.");
}

// ─────────────────────────────────────────────────────────────────────────
// 2. LOGGER (winston)
// ─────────────────────────────────────────────────────────────────────────

const logger = winston.createLogger({
  level: process.env.NODE_ENV === "production" ? "info" : "debug",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "recitech-backend" },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, timestamp, stack }) => `${timestamp} [${level}]: ${stack || message}`)
      ),
    }),
    ...(process.env.NODE_ENV === "test"
      ? []
      : [
          new winston.transports.File({ filename: "logs/error.log", level: "error" }),
          new winston.transports.File({ filename: "logs/combined.log" }),
        ]),
  ],
});

// ─────────────────────────────────────────────────────────────────────────
// 3. CONEXÃO MONGODB
// ─────────────────────────────────────────────────────────────────────────

mongoose.set("strictQuery", true);

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    logger.info(`MongoDB conectado: ${mongoose.connection.host}/${mongoose.connection.name}`);
  } catch (err) {
    logger.error(`Falha ao conectar no MongoDB: ${err.message}`);
    process.exit(1);
  }
};

mongoose.connection.on("disconnected", () => logger.warn("MongoDB desconectado"));

// ─────────────────────────────────────────────────────────────────────────
// 4. UTILS
// ─────────────────────────────────────────────────────────────────────────

/** Distância em km entre duas coordenadas (Haversine) — espelha `distanciaKm` do App.js */
function distanciaKm(lat1, lon1, lat2, lon2) {
  if ([lat1, lon1, lat2, lon2].some((v) => v === undefined || v === null || Number.isNaN(Number(v)))) {
    return null;
  }
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) * Math.cos((lat2 * Math.PI) / 180) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/** Evita try/catch repetido em handlers async */
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const signAccessToken = (userId) => jwt.sign({ sub: String(userId) }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

// ─────────────────────────────────────────────────────────────────────────
// 5. MODELS (Mongoose)
// ─────────────────────────────────────────────────────────────────────────

const TIPOS_USUARIO = ["pessoa_fisica", "condominio", "cooperativa", "empresa"];
const TIPOS_MATERIAL = [
  "plástico", "pet", "papel", "papelão", "metal", "alumínio",
  "vidro", "orgânico", "eletrônico", "borracha", "madeira", "têxtil",
];
const STATUS_NEGOCIACAO = [
  "aguardando_pagamento", "pagamento_aprovado", "em_coleta", "em_transporte", "finalizado", "cancelado",
];
const FORMAS_PAGAMENTO = ["dinheiro", "pix", "escrow"];
const MOTIVOS_DENUNCIA = [
  "Spam", "Golpe / Fraude", "Material inexistente", "Assédio",
  "Conteúdo inadequado", "Preço abusivo", "Dados falsos",
];

// --- User ---
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    password: { type: String, required: true, select: false },
    tipoUsuario: { type: String, enum: TIPOS_USUARIO, required: true },

    nomeCompleto: { type: String, trim: true, maxlength: 150 },
    nomeFantasia: { type: String, trim: true, maxlength: 150 },
    nomeEmpresa: { type: String, trim: true, maxlength: 150 }, // editável em EditarPerfilModal

    cpf: { type: String, trim: true },
    cnpj: { type: String, trim: true },

    telefone: { type: String, trim: true },
    cidade: { type: String, trim: true, maxlength: 100 },
    descricao: { type: String, trim: true, maxlength: 300 },
    areaAtuacao: { type: String, trim: true, maxlength: 150 },
    horarioAtendimento: { type: String, trim: true, maxlength: 100 },
    fotoPerfil: { type: String, default: null },

    latitude: { type: Number, default: null },
    longitude: { type: Number, default: null },

    verificado: { type: Boolean, default: false },
    empresaVerificada: { type: Boolean, default: false },

    kgTotal: { type: Number, default: 0 },
    totalNegociacoes: { type: Number, default: 0 },
    notaMedia: { type: Number, default: 0 },
    somaNotas: { type: Number, default: 0 },
    qtdAvaliacoes: { type: Number, default: 0 },

    ativo: { type: Boolean, default: true },
    resetPasswordToken: { type: String, select: false },
    resetPasswordExpires: { type: Date, select: false },
  },
  { timestamps: { createdAt: "criadoEm", updatedAt: "atualizadoEm" } }
);

userSchema.pre("save", async function hashPassword(next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, BCRYPT_SALT_ROUNDS);
  next();
});

userSchema.methods.compararSenha = function compararSenha(senhaTextoPlano) {
  return bcrypt.compare(senhaTextoPlano, this.password);
};

userSchema.methods.toPublicJSON = function toPublicJSON() {
  return {
    _id: this._id,
    email: this.email,
    tipoUsuario: this.tipoUsuario,
    nomeCompleto: this.nomeCompleto,
    nomeFantasia: this.nomeFantasia,
    nomeEmpresa: this.nomeEmpresa,
    cpf: this.cpf,
    cnpj: this.cnpj,
    telefone: this.telefone,
    cidade: this.cidade,
    descricao: this.descricao,
    areaAtuacao: this.areaAtuacao,
    horarioAtendimento: this.horarioAtendimento,
    fotoPerfil: this.fotoPerfil,
    verificado: this.verificado,
    empresaVerificada: this.empresaVerificada,
    kgTotal: this.kgTotal,
    totalNegociacoes: this.totalNegociacoes,
    notaMedia: this.notaMedia,
    criadoEm: this.criadoEm,
  };
};

userSchema.index({ cidade: 1 });
const User = mongoose.model("User", userSchema);

// --- Marketplace ---
const marketplaceSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    userEmail: { type: String, required: true },
    verificado: { type: Boolean, default: false },

    tipo: { type: String, enum: TIPOS_MATERIAL, required: true, index: true },
    quantidade: { type: Number, required: true, min: 0.01, max: 999999 },
    preco: { type: Number, required: true, min: 0.01, max: 99999 },
    precoNegociavel: { type: Boolean, default: true },
    descricao: { type: String, trim: true, maxlength: 500 },
    fotoBase64: { type: String, default: null },

    latitude: { type: Number, default: null },
    longitude: { type: Number, default: null },

    status: { type: String, enum: ["ativo", "pausado", "vendido"], default: "ativo", index: true },
  },
  { timestamps: { createdAt: "criadoEm", updatedAt: "atualizadoEm" } }
);
marketplaceSchema.index({ tipo: 1, status: 1, criadoEm: -1 });
marketplaceSchema.index({ descricao: "text" });
const Marketplace = mongoose.model("Marketplace", marketplaceSchema);

// --- Negociacao ---
const negociacaoSchema = new mongoose.Schema(
  {
    compradorId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    vendedorId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    materialId: { type: mongoose.Schema.Types.ObjectId, ref: "Marketplace", required: true },

    tipo: { type: String },
    compradorEmail: { type: String },
    vendedorEmail: { type: String },

    quantidade: { type: Number, required: true },
    precoUnitario: { type: Number, required: true },
    valorTotal: { type: Number, required: true },

    formaPagamento: { type: String, enum: FORMAS_PAGAMENTO, default: "dinheiro" },
    status: { type: String, enum: STATUS_NEGOCIACAO, default: "aguardando_pagamento", index: true },

    avaliado: { type: Boolean, default: false },
  },
  { timestamps: { createdAt: "criadoEm", updatedAt: "atualizadoEm" } }
);
const Negociacao = mongoose.model("Negociacao", negociacaoSchema);

// --- Chat ---
const chatSchema = new mongoose.Schema(
  {
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }],
    marketplaceId: { type: mongoose.Schema.Types.ObjectId, ref: "Marketplace", default: null },
    lastMessagePreview: { type: String, default: "" },
    lastMessageAt: { type: Date, default: Date.now },
    lastRead: { type: Map, of: Date, default: {} },
  },
  { timestamps: { createdAt: "criadoEm", updatedAt: "atualizadoEm" } }
);
chatSchema.index({ participants: 1 });
const Chat = mongoose.model("Chat", chatSchema);

// --- Message ---
const messageSchema = new mongoose.Schema(
  {
    chatId: { type: mongoose.Schema.Types.ObjectId, ref: "Chat", required: true, index: true },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    text: { type: String, required: true, trim: true, maxlength: 1000 },
  },
  { timestamps: { createdAt: "createdAt", updatedAt: false } }
);
messageSchema.index({ chatId: 1, createdAt: -1 });
const Message = mongoose.model("Message", messageSchema);

// --- Avaliacao ---
const avaliacaoSchema = new mongoose.Schema(
  {
    negociacaoId: { type: mongoose.Schema.Types.ObjectId, ref: "Negociacao", required: true },
    vendedorId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    autorId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    autorEmail: { type: String, required: true },
    nota: { type: Number, required: true, min: 1, max: 5 },
    comentario: { type: String, required: true, trim: true, maxlength: 400 },
  },
  { timestamps: { createdAt: "criadoEm", updatedAt: false } }
);
avaliacaoSchema.index({ negociacaoId: 1, autorId: 1 }, { unique: true });
const Avaliacao = mongoose.model("Avaliacao", avaliacaoSchema);

// --- Denuncia ---
const denunciaSchema = new mongoose.Schema(
  {
    tipo: { type: String, enum: ["usuario", "anuncio"], required: true },
    alvoId: { type: mongoose.Schema.Types.ObjectId, required: true },
    denuncianteId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    motivo: { type: String, enum: MOTIVOS_DENUNCIA, required: true },
    detalhe: { type: String, required: true, trim: true, maxlength: 500 },
    status: { type: String, enum: ["pendente", "revisado", "arquivado"], default: "pendente" },
  },
  { timestamps: { createdAt: "criadoEm", updatedAt: false } }
);
const Denuncia = mongoose.model("Denuncia", denunciaSchema);

// ─────────────────────────────────────────────────────────────────────────
// 6. VALIDAÇÃO (Joi schemas)
// ─────────────────────────────────────────────────────────────────────────

const schemas = {
  register: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    tipoUsuario: Joi.string().valid(...TIPOS_USUARIO).required(),
    nomeCompleto: Joi.string().trim().min(2).max(150).required(),
    nomeFantasia: Joi.string().trim().max(150).allow("", null),
    documento: Joi.string().trim().allow("", null),
    telefone: Joi.string().trim().pattern(/^\d{10,11}$/).allow("", null),
    cidade: Joi.string().trim().max(100).allow("", null),
  }),

  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),

  forgotPassword: Joi.object({
    email: Joi.string().email().required(),
  }),

  resetPassword: Joi.object({
    token: Joi.string().required(),
    password: Joi.string().min(6).required(),
  }),

  updateProfile: Joi.object({
    nomeEmpresa: Joi.string().trim().max(150).allow("", null),
    descricao: Joi.string().trim().max(300).allow("", null),
    horarioAtendimento: Joi.string().trim().max(100).allow("", null),
    areaAtuacao: Joi.string().trim().max(150).allow("", null),
    cidade: Joi.string().trim().max(100).allow("", null),
    fotoPerfil: Joi.string().allow("", null),
    cpf: Joi.string().trim().allow("", null),
    cnpj: Joi.string().trim().allow("", null),
    telefone: Joi.string().trim().pattern(/^\d{10,11}$/).allow("", null),
  }),

  marketplaceCreate: Joi.object({
    tipo: Joi.string().valid(...TIPOS_MATERIAL).required(),
    quantidade: Joi.number().positive().max(999999).required(),
    preco: Joi.number().positive().max(99999).required(),
    precoNegociavel: Joi.boolean().default(true),
    descricao: Joi.string().trim().max(500).allow("", null),
    fotoBase64: Joi.string().allow("", null),
    latitude: Joi.number().allow(null),
    longitude: Joi.number().allow(null),
  }),

  marketplaceBuy: Joi.object({
    itemId: Joi.string().hex().length(24).required(),
    quantidade: Joi.number().positive().required(),
    formaPagamento: Joi.string().valid(...FORMAS_PAGAMENTO).default("dinheiro"),
    precoProposto: Joi.number().positive().optional(),
  }),

  negociacaoStatus: Joi.object({
    status: Joi.string().valid(...STATUS_NEGOCIACAO).required(),
  }),

  denuncia: Joi.object({
    tipo: Joi.string().valid("usuario", "anuncio").required(),
    alvoId: Joi.string().hex().length(24).required(),
    motivo: Joi.string().valid(...MOTIVOS_DENUNCIA).required(),
    detalhe: Joi.string().trim().min(3).max(500).required(),
  }),

  avaliacao: Joi.object({
    negociacaoId: Joi.string().hex().length(24).required(),
    vendedorId: Joi.string().hex().length(24).required(),
    nota: Joi.number().integer().min(1).max(5).required(),
    comentario: Joi.string().trim().min(3).max(400).required(),
  }),

  chatCreate: Joi.object({
    otherUserId: Joi.string().hex().length(24).required(),
    marketplaceId: Joi.string().hex().length(24).allow(null),
  }),

  messageCreate: Joi.object({
    chatId: Joi.string().hex().length(24).required(),
    text: Joi.string().trim().min(1).max(1000).required(),
  }),
};

// ─────────────────────────────────────────────────────────────────────────
// 7. MIDDLEWARES
// ─────────────────────────────────────────────────────────────────────────

/** Valida req.body contra um schema Joi. 400 em caso de erro. */
const validate = (schema) => (req, res, next) => {
  const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
  if (error) {
    const message = error.details.map((d) => d.message).join("; ");
    return res.status(400).json({ success: false, error: message });
  }
  req.body = value;
  next();
};

/** Exige `Authorization: Bearer <token>`; popula req.userId */
const auth = (req, res, next) => {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ success: false, error: "Token de acesso ausente" });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub || payload.id;
    next();
  } catch (err) {
    const msg = err.name === "TokenExpiredError" ? "Token expirado" : "Token inválido";
    return res.status(401).json({ success: false, error: msg });
  }
};

const authLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MIN * 60 * 1000,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Muitas tentativas. Tente novamente em alguns minutos." },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: "Limite de requisições excedido. Aguarde e tente novamente." },
});

const notFound = (req, res) => {
  res.status(404).json({ success: false, error: `Rota não encontrada: ${req.method} ${req.originalUrl}` });
};

// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  if (statusCode >= 500) logger.error(err.stack || err.message);

  if (err.name === "ValidationError") {
    return res.status(400).json({ success: false, error: Object.values(err.errors).map((e) => e.message).join("; ") });
  }
  if (err.code === 11000) {
    const campo = Object.keys(err.keyPattern || { campo: 1 })[0];
    return res.status(409).json({ success: false, error: `Já existe um registro com esse ${campo}` });
  }
  if (err.name === "CastError") {
    return res.status(400).json({ success: false, error: "Identificador inválido" });
  }

  res.status(statusCode).json({ success: false, error: err.isOperational ? err.message : "Erro interno do servidor" });
};

// ─────────────────────────────────────────────────────────────────────────
// 8. SWAGGER
// ─────────────────────────────────────────────────────────────────────────

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: "3.0.0",
    info: {
      title: "ReciTech Marketplace API",
      version: "2.0.0",
      description: "API REST para o app ReciTech (App.js) — marketplace de materiais recicláveis, chat, negociações, avaliações e dashboard ESG.",
    },
    servers: [{ url: "/", description: "Servidor atual" }],
    components: {
      securitySchemes: { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" } },
    },
  },
  apis: [__filename], // lê as anotações @openapi deste mesmo arquivo
});

// ─────────────────────────────────────────────────────────────────────────
// 9. ROTAS / CONTROLLERS
// ─────────────────────────────────────────────────────────────────────────

const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: CLIENT_ORIGIN === "*" ? true : CLIENT_ORIGIN.split(",") }));
app.use(express.json({ limit: "10mb" })); // payload maior por causa de imagens base64
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(morgan("combined", { stream: { write: (msg) => logger.info(msg.trim()) } }));

app.get("/health", (req, res) => res.json({ success: true, status: "ok", timestamp: new Date().toISOString() }));
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(apiLimiter);

// ── AUTH ─────────────────────────────────────────────────────────────────

/**
 * @openapi
 * /register:
 *   post:
 *     summary: Cria uma nova conta (Pessoa Física, Condomínio, Cooperativa ou Empresa)
 *     tags: [Auth]
 */
app.post("/register", authLimiter, validate(schemas.register), asyncHandler(async (req, res) => {
  const { email, password, tipoUsuario, nomeCompleto, nomeFantasia, documento, telefone, cidade } = req.body;

  const existente = await User.findOne({ email: email.toLowerCase() });
  if (existente) return res.status(409).json({ success: false, error: "Já existe uma conta com esse email" });

  const dadosUsuario = {
    email, password, tipoUsuario, nomeCompleto,
    nomeFantasia: nomeFantasia || undefined,
    telefone: telefone || undefined,
    cidade: cidade || undefined,
  };

  let verificado = false;
  if (documento) {
    if (tipoUsuario === "pessoa_fisica") {
      if (!cpf.isValid(documento)) return res.status(400).json({ success: false, error: "CPF inválido" });
      dadosUsuario.cpf = documento;
      verificado = true;
    } else {
      if (!cnpj.isValid(documento)) return res.status(400).json({ success: false, error: "CNPJ inválido" });
      dadosUsuario.cnpj = documento;
      verificado = true;
    }
  }
  dadosUsuario.verificado = verificado;
  dadosUsuario.empresaVerificada = verificado && tipoUsuario !== "pessoa_fisica";

  const user = await User.create(dadosUsuario);
  const accessToken = signAccessToken(user._id);
  logger.info(`Novo usuário registrado: ${user.email} (${user.tipoUsuario})`);
  res.status(201).json({ success: true, accessToken, user: user.toPublicJSON() });
}));

/**
 * @openapi
 * /login:
 *   post:
 *     summary: Autentica usuário e retorna accessToken (JWT)
 *     tags: [Auth]
 */
app.post("/login", authLimiter, validate(schemas.login), asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() }).select("+password");
  if (!user || !user.ativo) return res.status(401).json({ success: false, error: "Credenciais inválidas" });

  const senhaOk = await user.compararSenha(password);
  if (!senhaOk) return res.status(401).json({ success: false, error: "Credenciais inválidas" });

  const accessToken = signAccessToken(user._id);
  res.json({ success: true, accessToken, user: user.toPublicJSON() });
}));

/**
 * @openapi
 * /forgot-password:
 *   post:
 *     summary: Solicita link de redefinição de senha
 *     tags: [Auth]
 */
app.post("/forgot-password", authLimiter, validate(schemas.forgotPassword), asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });

  if (!user) return res.json({ success: true, message: "Se o email existir, um link foi enviado." });

  const token = crypto.randomBytes(32).toString("hex");
  user.resetPasswordToken = crypto.createHash("sha256").update(token).digest("hex");
  user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // 1h
  await user.save();

  // TODO: integrar provedor de email real (SendGrid/SES). Por ora, logamos.
  logger.info(`Token de reset de senha para ${user.email}: ${token}`);
  res.json({ success: true, message: "Se o email existir, um link foi enviado." });
}));

/**
 * @openapi
 * /reset-password:
 *   post:
 *     summary: Redefine a senha usando o token recebido
 *     tags: [Auth]
 */
app.post("/reset-password", authLimiter, validate(schemas.resetPassword), asyncHandler(async (req, res) => {
  const { token, password } = req.body;
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

  const user = await User.findOne({
    resetPasswordToken: tokenHash,
    resetPasswordExpires: { $gt: Date.now() },
  }).select("+resetPasswordToken +resetPasswordExpires");

  if (!user) return res.status(400).json({ success: false, error: "Token inválido ou expirado" });

  user.password = password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  res.json({ success: true, message: "Senha atualizada com sucesso" });
}));

// ── USER ─────────────────────────────────────────────────────────────────

/**
 * @openapi
 * /user/profile:
 *   get:
 *     summary: Perfil do usuário autenticado
 *     tags: [User]
 *     security: [{ bearerAuth: [] }]
 *   put:
 *     summary: Edita o perfil do usuário autenticado
 *     tags: [User]
 *     security: [{ bearerAuth: [] }]
 */
app.get("/user/profile", auth, asyncHandler(async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ success: false, error: "Usuário não encontrado" });
  res.json({ success: true, user: user.toPublicJSON() });
}));

app.put("/user/profile", auth, validate(schemas.updateProfile), asyncHandler(async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ success: false, error: "Usuário não encontrado" });

  const campos = ["nomeEmpresa", "descricao", "horarioAtendimento", "areaAtuacao", "cidade", "fotoPerfil", "telefone"];
  campos.forEach((campo) => {
    if (req.body[campo] !== undefined) user[campo] = req.body[campo] || undefined;
  });

  if (req.body.cpf) {
    if (!cpf.isValid(req.body.cpf)) return res.status(400).json({ success: false, error: "CPF inválido" });
    user.cpf = req.body.cpf;
    if (user.tipoUsuario === "pessoa_fisica") user.verificado = true;
  }
  if (req.body.cnpj) {
    if (!cnpj.isValid(req.body.cnpj)) return res.status(400).json({ success: false, error: "CNPJ inválido" });
    user.cnpj = req.body.cnpj;
    if (user.tipoUsuario !== "pessoa_fisica") {
      user.verificado = true;
      user.empresaVerificada = true;
    }
  }

  await user.save();
  res.json({ success: true, user: user.toPublicJSON() });
}));

/**
 * @openapi
 * /user/{id}/profile:
 *   get:
 *     summary: Perfil público de um usuário
 *     tags: [User]
 *     security: [{ bearerAuth: [] }]
 */
app.get("/user/:id/profile", auth, asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ success: false, error: "Usuário não encontrado" });
  res.json({ success: true, user: user.toPublicJSON() });
}));

/**
 * @openapi
 * /user/{id}/reviews:
 *   get:
 *     summary: Avaliações recebidas por um usuário
 *     tags: [User]
 *     security: [{ bearerAuth: [] }]
 */
app.get("/user/:id/reviews", auth, asyncHandler(async (req, res) => {
  const reviews = await Avaliacao.find({ vendedorId: req.params.id }).sort({ criadoEm: -1 }).limit(50).lean();
  res.json({
    success: true,
    reviews: reviews.map((r) => ({
      _id: r._id, nota: r.nota, comentario: r.comentario, autorEmail: r.autorEmail, criadoEm: r.criadoEm,
    })),
  });
}));

// ── MARKETPLACE ──────────────────────────────────────────────────────────

const CAP_GEO_CANDIDATOS = 500;

const paraPublicoMaterial = (item) => {
  const vendedor = item.userId && item.userId._id ? item.userId : null;
  return {
    _id: item._id,
    tipo: item.tipo,
    quantidade: item.quantidade,
    preco: item.preco,
    precoNegociavel: item.precoNegociavel,
    descricao: item.descricao,
    fotoBase64: item.fotoBase64,
    latitude: item.latitude,
    longitude: item.longitude,
    criadoEm: item.criadoEm,
    userId: vendedor ? String(vendedor._id) : String(item.userId),
    userEmail: vendedor ? vendedor.email : item.userEmail,
    vendedorNome: vendedor ? vendedor.nomeEmpresa || vendedor.nomeCompleto : undefined,
    vendedorVerificado: vendedor ? vendedor.verificado : item.verificado,
    vendedorEmpresaVerificada: vendedor ? vendedor.empresaVerificada : false,
    vendedorNota: vendedor ? vendedor.notaMedia : 0,
    vendedorNegociacoes: vendedor ? vendedor.totalNegociacoes : 0,
    vendedorKgTotal: vendedor ? vendedor.kgTotal : 0,
  };
};

/**
 * @openapi
 * /marketplace:
 *   get:
 *     summary: Lista anúncios com filtros e paginação
 *     tags: [Marketplace]
 *     security: [{ bearerAuth: [] }]
 *   post:
 *     summary: Publica um novo anúncio de material reciclável
 *     tags: [Marketplace]
 *     security: [{ bearerAuth: [] }]
 */
app.get("/marketplace", auth, asyncHandler(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));

  const filtro = { status: "ativo" };
  if (req.query.tipo) filtro.tipo = req.query.tipo;
  if (req.query.verificado === "true") filtro.verificado = true;
  if (req.query.precMax) filtro.preco = { ...filtro.preco, $lte: Number(req.query.precMax) };
  if (req.query.qtdMin) filtro.quantidade = { ...filtro.quantidade, $gte: Number(req.query.qtdMin) };
  if (req.query.q) {
    const termo = String(req.query.q).trim();
    filtro.$or = [
      { descricao: { $regex: termo, $options: "i" } },
      { tipo: { $regex: termo, $options: "i" } },
    ];
  }

  const popSelect = "email nomeEmpresa nomeCompleto verificado empresaVerificada notaMedia totalNegociacoes kgTotal";
  const temFiltroGeo = req.query.lat && req.query.lon && req.query.raio;

  if (!temFiltroGeo) {
    const [docs, total] = await Promise.all([
      Marketplace.find(filtro).populate("userId", popSelect).sort({ criadoEm: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Marketplace.countDocuments(filtro),
    ]);
    return res.json({ success: true, materials: docs.map(paraPublicoMaterial), total, page, limit });
  }

  const candidatos = await Marketplace.find(filtro).populate("userId", popSelect).sort({ criadoEm: -1 }).limit(CAP_GEO_CANDIDATOS).lean();
  const lat = Number(req.query.lat);
  const lon = Number(req.query.lon);
  const raio = Number(req.query.raio);

  const dentroDoRaio = candidatos.filter((item) => {
    if (item.latitude === null || item.latitude === undefined) return false;
    const d = distanciaKm(lat, lon, item.latitude, item.longitude);
    return d !== null && d <= raio;
  });

  const total = dentroDoRaio.length;
  const pagina = dentroDoRaio.slice((page - 1) * limit, page * limit);
  res.json({ success: true, materials: pagina.map(paraPublicoMaterial), total, page, limit });
}));

app.post("/marketplace", auth, validate(schemas.marketplaceCreate), asyncHandler(async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ success: false, error: "Usuário não encontrado" });

  const item = await Marketplace.create({
    ...req.body, userId: user._id, userEmail: user.email, verificado: user.verificado,
  });

  res.status(201).json({ success: true, material: paraPublicoMaterial({ ...item.toObject(), userId: user }) });
}));

/**
 * @openapi
 * /marketplace/buy:
 *   post:
 *     summary: Compra (ou propõe compra) de um anúncio, cria negociação
 *     tags: [Marketplace]
 *     security: [{ bearerAuth: [] }]
 */
app.post("/marketplace/buy", auth, validate(schemas.marketplaceBuy), asyncHandler(async (req, res) => {
  const { itemId, quantidade, formaPagamento, precoProposto } = req.body;

  if (!mongoose.Types.ObjectId.isValid(itemId)) {
    return res.status(400).json({ success: false, error: "Anúncio inválido" });
  }

  const item = await Marketplace.findById(itemId);
  if (!item || item.status !== "ativo") {
    return res.status(404).json({ success: false, error: "Anúncio não encontrado ou indisponível" });
  }
  if (String(item.userId) === String(req.userId)) {
    return res.status(400).json({ success: false, error: "Você não pode comprar seu próprio anúncio" });
  }
  if (quantidade > item.quantidade) {
    return res.status(400).json({ success: false, error: "Quantidade solicitada maior que o disponível" });
  }

  const comprador = await User.findById(req.userId);
  const vendedor = await User.findById(item.userId);
  if (!vendedor) return res.status(404).json({ success: false, error: "Vendedor não encontrado" });

  const precoUnitario = precoProposto !== undefined ? precoProposto : item.preco;
  const valorTotal = Number((precoUnitario * quantidade).toFixed(2));

  const negociacao = await Negociacao.create({
    compradorId: comprador._id,
    vendedorId: vendedor._id,
    materialId: item._id,
    tipo: item.tipo,
    compradorEmail: comprador.email,
    vendedorEmail: vendedor.email,
    quantidade,
    precoUnitario,
    valorTotal,
    formaPagamento,
    status: formaPagamento === "dinheiro" ? "pagamento_aprovado" : "aguardando_pagamento",
  });

  item.quantidade -= quantidade;
  if (item.quantidade <= 0) {
    item.quantidade = 0;
    item.status = "vendido";
  }
  await item.save();

  vendedor.kgTotal += quantidade;
  vendedor.totalNegociacoes += 1;
  await vendedor.save();

  res.status(201).json({ success: true, negociacaoId: negociacao._id, valor: valorTotal, status: negociacao.status });
}));

// ── NEGOCIAÇÕES ──────────────────────────────────────────────────────────

/**
 * @openapi
 * /negociacoes:
 *   get:
 *     summary: Lista as negociações do usuário (como comprador ou vendedor)
 *     tags: [Negociacoes]
 *     security: [{ bearerAuth: [] }]
 */
app.get("/negociacoes", auth, asyncHandler(async (req, res) => {
  const negociacoes = await Negociacao.find({
    $or: [{ compradorId: req.userId }, { vendedorId: req.userId }],
  }).sort({ criadoEm: -1 }).lean();

  res.json({
    success: true,
    negociacoes: negociacoes.map((n) => ({
      _id: n._id,
      tipo: n.tipo,
      quantidade: n.quantidade,
      valorTotal: n.valorTotal,
      status: n.status,
      formaPagamento: n.formaPagamento,
      compradorId: String(n.compradorId),
      vendedorId: String(n.vendedorId),
      compradorEmail: n.compradorEmail,
      vendedorEmail: n.vendedorEmail,
      avaliado: n.avaliado,
      criadoEm: n.criadoEm,
    })),
  });
}));

/**
 * @openapi
 * /negociacoes/{id}/status:
 *   put:
 *     summary: Atualiza o status de uma negociação (apenas vendedor)
 *     tags: [Negociacoes]
 *     security: [{ bearerAuth: [] }]
 */
app.put("/negociacoes/:id/status", auth, validate(schemas.negociacaoStatus), asyncHandler(async (req, res) => {
  const { status } = req.body;
  const negociacao = await Negociacao.findById(req.params.id);

  if (!negociacao) return res.status(404).json({ success: false, error: "Negociação não encontrada" });
  if (String(negociacao.vendedorId) !== String(req.userId)) {
    return res.status(403).json({ success: false, error: "Apenas o vendedor pode atualizar o status" });
  }
  if (["finalizado", "cancelado"].includes(negociacao.status)) {
    return res.status(400).json({ success: false, error: "Negociação já encerrada" });
  }

  negociacao.status = status;
  await negociacao.save();
  res.json({ success: true, negociacao: { _id: negociacao._id, status: negociacao.status } });
}));

// ── AVALIAÇÕES / DENÚNCIAS ───────────────────────────────────────────────

/**
 * @openapi
 * /avaliacoes:
 *   post:
 *     summary: Avalia o vendedor de uma negociação finalizada
 *     tags: [Reputacao]
 *     security: [{ bearerAuth: [] }]
 */
app.post("/avaliacoes", auth, validate(schemas.avaliacao), asyncHandler(async (req, res) => {
  const { negociacaoId, vendedorId, nota, comentario } = req.body;

  const negociacao = await Negociacao.findById(negociacaoId);
  if (!negociacao) return res.status(404).json({ success: false, error: "Negociação não encontrada" });
  if (String(negociacao.compradorId) !== String(req.userId)) {
    return res.status(403).json({ success: false, error: "Apenas o comprador pode avaliar esta negociação" });
  }
  if (negociacao.status !== "finalizado") {
    return res.status(400).json({ success: false, error: "A negociação ainda não foi finalizada" });
  }
  if (negociacao.avaliado) {
    return res.status(409).json({ success: false, error: "Esta negociação já foi avaliada" });
  }
  if (String(negociacao.vendedorId) !== String(vendedorId)) {
    return res.status(400).json({ success: false, error: "Vendedor não corresponde à negociação" });
  }

  const autor = await User.findById(req.userId);
  const avaliacao = await Avaliacao.create({
    negociacaoId, vendedorId, autorId: req.userId, autorEmail: autor.email, nota, comentario,
  });

  negociacao.avaliado = true;
  await negociacao.save();

  const vendedor = await User.findById(vendedorId);
  vendedor.somaNotas += nota;
  vendedor.qtdAvaliacoes += 1;
  vendedor.notaMedia = Number((vendedor.somaNotas / vendedor.qtdAvaliacoes).toFixed(2));
  await vendedor.save();

  res.status(201).json({ success: true, avaliacao });
}));

/**
 * @openapi
 * /denuncias:
 *   post:
 *     summary: Denuncia um usuário ou anúncio
 *     tags: [Reputacao]
 *     security: [{ bearerAuth: [] }]
 */
app.post("/denuncias", auth, validate(schemas.denuncia), asyncHandler(async (req, res) => {
  const { tipo, alvoId, motivo, detalhe } = req.body;
  const denuncia = await Denuncia.create({ tipo, alvoId, motivo, detalhe, denuncianteId: req.userId });
  res.status(201).json({ success: true, denunciaId: denuncia._id });
}));

// ── CHAT / MENSAGENS ─────────────────────────────────────────────────────

/**
 * @openapi
 * /chats:
 *   get:
 *     summary: Lista as conversas do usuário autenticado
 *     tags: [Chat]
 *     security: [{ bearerAuth: [] }]
 *   post:
 *     summary: Cria (ou reaproveita) uma conversa com outro usuário
 *     tags: [Chat]
 *     security: [{ bearerAuth: [] }]
 */
app.get("/chats", auth, asyncHandler(async (req, res) => {
  const chats = await Chat.find({ participants: req.userId })
    .populate("participants", "email nomeEmpresa nomeCompleto fotoPerfil verificado")
    .sort({ lastMessageAt: -1 })
    .lean();

  const chatsComNaoLidas = await Promise.all(
    chats.map(async (chat) => {
      const ultimaLeitura = chat.lastRead?.[String(req.userId)] || new Date(0);
      const naoLidas = await Message.countDocuments({
        chatId: chat._id, senderId: { $ne: req.userId }, createdAt: { $gt: ultimaLeitura },
      });
      return {
        _id: chat._id,
        participants: chat.participants,
        lastMessagePreview: chat.lastMessagePreview,
        lastMessageAt: chat.lastMessageAt,
        naoLidas,
      };
    })
  );

  res.json({ success: true, chats: chatsComNaoLidas });
}));

app.post("/chats", auth, validate(schemas.chatCreate), asyncHandler(async (req, res) => {
  const { otherUserId, marketplaceId } = req.body;

  if (String(otherUserId) === String(req.userId)) {
    return res.status(400).json({ success: false, error: "Você não pode conversar com você mesmo" });
  }

  const outroUsuario = await User.findById(otherUserId);
  if (!outroUsuario) return res.status(404).json({ success: false, error: "Usuário não encontrado" });

  const filtro = {
    participants: { $all: [req.userId, otherUserId], $size: 2 },
    ...(marketplaceId ? { marketplaceId } : {}),
  };

  let chat = await Chat.findOne(filtro);
  if (!chat) {
    chat = await Chat.create({ participants: [req.userId, otherUserId], marketplaceId: marketplaceId || null });
  }

  res.status(201).json({ success: true, chatId: chat._id });
}));

const garantirParticipante = async (chatId, userId) => {
  const chat = await Chat.findById(chatId);
  if (!chat) return null;
  const ehParticipante = chat.participants.some((p) => String(p) === String(userId));
  return ehParticipante ? chat : false;
};

/**
 * @openapi
 * /messages/{chatId}:
 *   get:
 *     summary: Histórico de mensagens paginado (mais recentes primeiro)
 *     tags: [Chat]
 *     security: [{ bearerAuth: [] }]
 */
app.get("/messages/:chatId", auth, asyncHandler(async (req, res) => {
  const { chatId } = req.params;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));

  const chat = await garantirParticipante(chatId, req.userId);
  if (chat === null) return res.status(404).json({ success: false, error: "Conversa não encontrada" });
  if (chat === false) return res.status(403).json({ success: false, error: "Acesso negado a esta conversa" });

  const messages = await Message.find({ chatId }).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean();

  chat.lastRead.set(String(req.userId), new Date());
  await chat.save();

  res.json({ success: true, messages });
}));

/**
 * @openapi
 * /messages:
 *   post:
 *     summary: Envia uma mensagem em uma conversa
 *     tags: [Chat]
 *     security: [{ bearerAuth: [] }]
 */
app.post("/messages", auth, validate(schemas.messageCreate), asyncHandler(async (req, res) => {
  const { chatId, text } = req.body;

  const chat = await garantirParticipante(chatId, req.userId);
  if (chat === null) return res.status(404).json({ success: false, error: "Conversa não encontrada" });
  if (chat === false) return res.status(403).json({ success: false, error: "Acesso negado a esta conversa" });

  const message = await Message.create({ chatId, senderId: req.userId, text });

  chat.lastMessagePreview = text.slice(0, 120);
  chat.lastMessageAt = message.createdAt;
  chat.lastRead.set(String(req.userId), message.createdAt);
  await chat.save();

  res.status(201).json({ success: true, message });
}));

// ── ESG ──────────────────────────────────────────────────────────────────

/**
 * @openapi
 * /esg/dashboard:
 *   get:
 *     summary: Métricas coletivas de impacto ambiental (kg reciclado, CO2 evitado, etc.)
 *     tags: [ESG]
 *     security: [{ bearerAuth: [] }]
 */
app.get("/esg/dashboard", auth, asyncHandler(async (req, res) => {
  const [agregado, porMaterial] = await Promise.all([
    Negociacao.aggregate([
      { $group: { _id: null, totalKg: { $sum: "$quantidade" }, negociacoes: { $sum: 1 }, usuarios: { $addToSet: "$vendedorId" } } },
    ]),
    Negociacao.aggregate([{ $group: { _id: "$tipo", kg: { $sum: "$quantidade" } } }, { $sort: { kg: -1 } }]),
  ]);

  const totalKg = agregado[0]?.totalKg || 0;
  const negociacoes = agregado[0]?.negociacoes || 0;
  const usuariosAtivos = agregado[0]?.usuarios?.length || 0;

  const materiais = {};
  porMaterial.forEach((m) => { if (m._id) materiais[m._id] = m.kg; });

  res.json({
    success: true,
    dados: { totalKg, co2Evitado: Number((totalKg * 2.5).toFixed(1)), usuariosAtivos, negociacoes, materiais },
  });
}));

// ── 404 / erros ──────────────────────────────────────────────────────────

app.use(notFound);
app.use(errorHandler);

// ─────────────────────────────────────────────────────────────────────────
// 10. BOOT DO SERVIDOR
// ─────────────────────────────────────────────────────────────────────────

const start = async () => {
  await connectDB();

  const server = app.listen(PORT, () => {
    logger.info(`ReciTech backend rodando na porta ${PORT}`);
    logger.info(`Swagger docs disponível em http://localhost:${PORT}/api-docs`);
  });

  const shutdown = (signal) => {
    logger.info(`${signal} recebido, encerrando servidor...`);
    server.close(() => process.exit(0));
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
};

if (require.main === module) {
  start();
}

module.exports = app; // permite importar `app` em testes (supertest) sem subir o servidor

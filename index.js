/**
 * ReciTech Marketplace API
 * Backend compatível com o frontend App(6).js
 *
 * Variáveis de ambiente:
 * MONGODB_URI=mongodb://localhost:27017/recitech
 * JWT_SECRET=troque-esta-chave-em-producao
 * PORT=3000
 *
 * Dependências esperadas:
 * express mongoose bcryptjs jsonwebtoken cors dotenv
 */

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "recitech-development-secret-change-me";

if (!MONGODB_URI) {
  console.warn("⚠️ MONGODB_URI/MONGO_URI não configurada.");
}

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

const TIPOS_USUARIO = [
  "pessoa_fisica",
  "condominio",
  "cooperativa",
  "empresa",
];

const TIPOS_MATERIAL = [
  "plástico",
  "pet",
  "papel",
  "papelão",
  "metal",
  "alumínio",
  "vidro",
  "orgânico",
  "eletrônico",
  "borracha",
  "madeira",
  "têxtil",
];

const STATUS_NEGOCIACAO = [
  "aguardando_pagamento",
  "pagamento_aprovado",
  "em_coleta",
  "em_transporte",
  "finalizado",
  "cancelado",
];

const FORMAS_PAGAMENTO = ["dinheiro", "pix", "escrow"];
const MOTIVOS_DENUNCIA = [
  "Spam",
  "Golpe / Fraude",
  "Material inexistente",
  "Assédio",
  "Conteúdo inadequado",
  "Preço abusivo",
  "Dados falsos",
];

const sanitize = (value) =>
  String(value ?? "")
    .replace(/<[^>]*>/g, "")
    .replace(/[<>"'&]/g, "")
    .trim();

const isEmail = (value) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());

const digits = (value) => String(value || "").replace(/\D/g, "");

const isCPF = (value) => digits(value).length === 11;
const isCNPJ = (value) => digits(value).length === 14;

const isValidObjectId = (value) => mongoose.Types.ObjectId.isValid(value);

const signToken = (user) =>
  jwt.sign(
    {
      sub: user._id.toString(),
      email: user.email,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

const publicUser = (user) => {
  if (!user) return null;

  return {
    _id: user._id,
    email: user.email,
    tipoUsuario: user.tipoUsuario,
    nomeCompleto: user.nomeCompleto,
    nomeEmpresa: user.nomeEmpresa,
    nomeFantasia: user.nomeFantasia,
    descricao: user.descricao,
    cidade: user.cidade,
    areaAtuacao: user.areaAtuacao,
    horarioAtendimento: user.horarioAtendimento,
    telefone: user.telefone,
    fotoPerfil: user.fotoPerfil,
    verificado: Boolean(user.verificado),
    empresaVerificada: Boolean(user.empresaVerificada),
    cpf: user.cpf ? "***********" : "",
    cnpj: user.cnpj ? "**************" : "",
    kgTotal: Number(user.kgTotal || 0),
    totalNegociacoes: Number(user.totalNegociacoes || 0),
    notaMedia: Number(user.notaMedia || 0),
    criadoEm: user.createdAt,
  };
};

const calculateDistanceKm = (lat1, lon1, lat2, lon2) => {
  if (
    lat1 === undefined ||
    lon1 === undefined ||
    lat2 === undefined ||
    lon2 === undefined
  ) {
    return null;
  }

  const R = 6371;
  const dLat = ((Number(lat2) - Number(lat1)) * Math.PI) / 180;
  const dLon = ((Number(lon2) - Number(lon1)) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((Number(lat1) * Math.PI) / 180) *
      Math.cos((Number(lat2) * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;

  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
};

const getBadge = (kg = 0) => {
  if (kg >= 2000) return "lenda";
  if (kg >= 1000) return "campeao";
  if (kg >= 500) return "top";
  if (kg >= 100) return "ativo";
  return "iniciante";
};

const parsePositive = (value) => {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : null;
};

const asyncRoute = (handler) => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch(next);

// -----------------------------------------------------------------------------
// Schemas
// -----------------------------------------------------------------------------

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    passwordHash: {
      type: String,
      required: true,
      select: false,
    },

    tipoUsuario: {
      type: String,
      enum: TIPOS_USUARIO,
      default: "pessoa_fisica",
    },

    nomeCompleto: { type: String, trim: true, maxlength: 120 },
    nomeFantasia: { type: String, trim: true, maxlength: 80 },
    nomeEmpresa: { type: String, trim: true, maxlength: 120 },

    cpf: { type: String, default: "" },
    cnpj: { type: String, default: "" },
    telefone: { type: String, default: "" },
    cidade: { type: String, default: "", maxlength: 80 },

    descricao: { type: String, default: "", maxlength: 300 },
    horarioAtendimento: { type: String, default: "", maxlength: 100 },
    areaAtuacao: { type: String, default: "", maxlength: 120 },

    fotoPerfil: { type: String, default: "" },

    verificado: { type: Boolean, default: false },
    empresaVerificada: { type: Boolean, default: false },

    kgTotal: { type: Number, default: 0 },
    totalNegociacoes: { type: Number, default: 0 },
    notaMedia: { type: Number, default: 0 },

    resetTokenHash: { type: String, default: "" },
    resetTokenExpires: { type: Date, default: null },
  },
  { timestamps: true }
);

const materialSchema = new mongoose.Schema(
  {
    tipo: {
      type: String,
      enum: TIPOS_MATERIAL,
      required: true,
      index: true,
    },
    quantidade: { type: Number, required: true, min: 0 },
    quantidadeInicial: { type: Number, required: true, min: 0 },

    preco: { type: Number, required: true, min: 0 },
    precoNegociavel: { type: Boolean, default: true },

    descricao: { type: String, default: "", maxlength: 500 },
    fotoBase64: { type: String, default: "" },

    latitude: Number,
    longitude: Number,

    disponivel: { type: Boolean, default: true, index: true },

    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
  },
  { timestamps: true }
);

const negotiationSchema = new mongoose.Schema(
  {
    materialId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Material",
      default: null,
    },

    vendedorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    compradorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    vendedorEmail: String,
    compradorEmail: String,

    tipo: String,
    quantidade: { type: Number, required: true, min: 0 },

    precoPorKg: { type: Number, required: true, min: 0 },
    valorTotal: { type: Number, required: true, min: 0 },
    taxaPlataforma: { type: Number, default: 0.03 },

    precoProposto: { type: Number, default: null },

    formaPagamento: {
      type: String,
      enum: FORMAS_PAGAMENTO,
      default: "dinheiro",
    },

    status: {
      type: String,
      enum: STATUS_NEGOCIACAO,
      default: "aguardando_pagamento",
    },

    avaliado: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const chatSchema = new mongoose.Schema(
  {
    participants: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],
    marketplaceId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Material",
      default: null,
    },
    lastMessage: { type: String, default: "" },
    lastMessageAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const messageSchema = new mongoose.Schema(
  {
    chatId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Chat",
      required: true,
      index: true,
    },
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    text: {
      type: String,
      required: true,
      maxlength: 1000,
    },
  },
  { timestamps: true }
);

const reviewSchema = new mongoose.Schema(
  {
    negociacaoId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Negotiation",
      required: true,
    },
    vendedorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    autorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    nota: {
      type: Number,
      min: 1,
      max: 5,
      required: true,
    },
    comentario: {
      type: String,
      required: true,
      maxlength: 400,
    },
  },
  { timestamps: true }
);

const complaintSchema = new mongoose.Schema(
  {
    tipo: {
      type: String,
      enum: ["usuario", "anuncio"],
      required: true,
    },
    alvoId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
    },
    autorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    motivo: String,
    detalhe: { type: String, maxlength: 500 },
    status: {
      type: String,
      enum: ["aberta", "em_analise", "resolvida"],
      default: "aberta",
    },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);
const Negotiation = mongoose.model("Negotiation", negotiationSchema);
const Chat = mongoose.model("Chat", chatSchema);
const Message = mongoose.model("Message", messageSchema);
const Review = mongoose.model("Review", reviewSchema);
const Complaint = mongoose.model("Complaint", complaintSchema);

// -----------------------------------------------------------------------------
// Auth middleware
// -----------------------------------------------------------------------------

const auth = asyncRoute(async (req, res, next) => {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      error: "Token não informado",
    });
  }

  const token = header.slice(7);

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: "Usuário não encontrado",
      });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({
      success: false,
      error: "Token inválido ou expirado",
    });
  }
});

// -----------------------------------------------------------------------------
// Health
// -----------------------------------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "ReciTech Marketplace API",
    version: "2.0.0",
    status: "online",
  });
});

app.get("/health", asyncRoute(async (req, res) => {
  res.json({
    success: true,
    api: "online",
    database:
      mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    timestamp: new Date().toISOString(),
  });
}));

// -----------------------------------------------------------------------------
// Authentication
// -----------------------------------------------------------------------------

app.post(
  "/register",
  asyncRoute(async (req, res) => {
    const {
      email,
      password,
      tipoUsuario,
      nomeCompleto,
      nomeFantasia,
      documento,
      telefone,
      cidade,
    } = req.body;

    const normalizedEmail = String(email || "").trim().toLowerCase();

    if (!isEmail(normalizedEmail)) {
      return res.status(400).json({
        success: false,
        error: "Email inválido",
      });
    }

    if (!password || String(password).length < 6) {
      return res.status(400).json({
        success: false,
        error: "Senha deve ter pelo menos 6 caracteres",
      });
    }

    if (!TIPOS_USUARIO.includes(tipoUsuario)) {
      return res.status(400).json({
        success: false,
        error: "Tipo de usuário inválido",
      });
    }

    if (!String(nomeCompleto || "").trim()) {
      return res.status(400).json({
        success: false,
        error: "Nome ou razão social é obrigatório",
      });
    }

    const existing = await User.findOne({ email: normalizedEmail });

    if (existing) {
      return res.status(409).json({
        success: false,
        error: "Este email já está cadastrado",
      });
    }

    const doc = digits(documento);

    if (doc) {
      const valid =
        tipoUsuario === "pessoa_fisica" ? isCPF(doc) : isCNPJ(doc);

      if (!valid) {
        return res.status(400).json({
          success: false,
          error:
            tipoUsuario === "pessoa_fisica"
              ? "CPF deve possuir 11 dígitos"
              : "CNPJ deve possuir 14 dígitos",
        });
      }
    }

    const passwordHash = await bcrypt.hash(String(password), 12);

    const user = await User.create({
      email: normalizedEmail,
      passwordHash,
      tipoUsuario,
      nomeCompleto: sanitize(nomeCompleto),
      nomeFantasia: sanitize(nomeFantasia),
      nomeEmpresa: sanitize(nomeCompleto),
      cpf: tipoUsuario === "pessoa_fisica" ? doc : "",
      cnpj: tipoUsuario !== "pessoa_fisica" ? doc : "",
      telefone: digits(telefone),
      cidade: sanitize(cidade),
      verificado: Boolean(doc),
      empresaVerificada: tipoUsuario !== "pessoa_fisica" && Boolean(doc),
    });

    const accessToken = signToken(user);

    res.status(201).json({
      success: true,
      accessToken,
      user: publicUser(user),
    });
  })
);

app.post(
  "/login",
  asyncRoute(async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!isEmail(email) || !password) {
      return res.status(400).json({
        success: false,
        error: "Email e senha são obrigatórios",
      });
    }

    const user = await User.findOne({ email }).select("+passwordHash");

    if (!user) {
      return res.status(401).json({
        success: false,
        error: "Credenciais inválidas",
      });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);

    if (!valid) {
      return res.status(401).json({
        success: false,
        error: "Credenciais inválidas",
      });
    }

    const accessToken = signToken(user);

    res.json({
      success: true,
      accessToken,
      user: publicUser(user),
    });
  })
);

app.post(
  "/forgot-password",
  asyncRoute(async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();

    if (!isEmail(email)) {
      return res.status(400).json({
        success: false,
        error: "Email inválido",
      });
    }

    const user = await User.findOne({ email });

    // Resposta genérica para não revelar se um email existe.
    if (!user) {
      return res.json({
        success: true,
        message: "Se o email estiver cadastrado, as instruções serão enviadas.",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    const hash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetTokenHash = hash;
    user.resetTokenExpires = new Date(Date.now() + 30 * 60 * 1000);
    await user.save();

    // Integração de email pode ser adicionada aqui.
    // Em desenvolvimento, mostramos apenas no log do servidor.
    console.log(
      `🔐 Token de recuperação para ${email}: ${rawToken}`
    );

    res.json({
      success: true,
      message: "Se o email estiver cadastrado, as instruções serão enviadas.",
    });
  })
);

// Opcional para uma futura tela de redefinição de senha.
app.post(
  "/reset-password",
  asyncRoute(async (req, res) => {
    const { token, password } = req.body;

    if (!token || String(password || "").length < 6) {
      return res.status(400).json({
        success: false,
        error: "Token e nova senha válida são obrigatórios",
      });
    }

    const hash = crypto
      .createHash("sha256")
      .update(String(token))
      .digest("hex");

    const user = await User.findOne({
      resetTokenHash: hash,
      resetTokenExpires: { $gt: new Date() },
    }).select("+passwordHash");

    if (!user) {
      return res.status(400).json({
        success: false,
        error: "Token inválido ou expirado",
      });
    }

    user.passwordHash = await bcrypt.hash(String(password), 12);
    user.resetTokenHash = "";
    user.resetTokenExpires = null;

    await user.save();

    res.json({
      success: true,
      message: "Senha alterada com sucesso",
    });
  })
);

// -----------------------------------------------------------------------------
// User profile
// -----------------------------------------------------------------------------

app.get(
  "/user/profile",
  auth,
  asyncRoute(async (req, res) => {
    res.json({
      success: true,
      user: publicUser(req.user),
    });
  })
);

app.put(
  "/user/profile",
  auth,
  asyncRoute(async (req, res) => {
    const {
      nomeEmpresa,
      descricao,
      horarioAtendimento,
      areaAtuacao,
      cidade,
      fotoPerfil,
      cpf,
      cnpj,
      telefone,
    } = req.body;

    if (descricao && String(descricao).length > 300) {
      return res.status(400).json({
        success: false,
        error: "Descrição muito longa (máx. 300 caracteres)",
      });
    }

    if (telefone && digits(telefone).length < 10) {
      return res.status(400).json({
        success: false,
        error: "Telefone inválido",
      });
    }

    if (cpf && !isCPF(cpf)) {
      return res.status(400).json({
        success: false,
        error: "CPF inválido",
      });
    }

    if (cnpj && !isCNPJ(cnpj)) {
      return res.status(400).json({
        success: false,
        error: "CNPJ inválido",
      });
    }

    // Evita que o cliente altere email, tipo, senha ou métricas diretamente.
    req.user.nomeEmpresa = sanitize(nomeEmpresa);
    req.user.descricao = sanitize(descricao);
    req.user.horarioAtendimento = sanitize(horarioAtendimento);
    req.user.areaAtuacao = sanitize(areaAtuacao);
    req.user.cidade = sanitize(cidade);
    req.user.telefone = digits(telefone);
    req.user.cpf = digits(cpf);
    req.user.cnpj = digits(cnpj);

    if (typeof fotoPerfil === "string") {
      // Limite simples para evitar documentos Mongo excessivamente grandes.
      if (fotoPerfil.length > 7 * 1024 * 1024) {
        return res.status(400).json({
          success: false,
          error: "Foto muito grande",
        });
      }
      req.user.fotoPerfil = fotoPerfil;
    }

    req.user.verificado = Boolean(req.user.cpf || req.user.cnpj);
    req.user.empresaVerificada =
      req.user.tipoUsuario !== "pessoa_fisica" && Boolean(req.user.cnpj);

    await req.user.save();

    res.json({
      success: true,
      user: publicUser(req.user),
    });
  })
);

app.get(
  "/user/:id/profile",
  auth,
  asyncRoute(async (req, res) => {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: "ID inválido",
      });
    }

    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "Perfil não encontrado",
      });
    }

    res.json({
      success: true,
      user: publicUser(user),
    });
  })
);

// -----------------------------------------------------------------------------
// Marketplace
// -----------------------------------------------------------------------------

app.get(
  "/marketplace",
  auth,
  asyncRoute(async (req, res) => {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 10));

    const {
      tipo,
      verificado,
      precMax,
      qtdMin,
      q,
      lat,
      lon,
      raio,
    } = req.query;

    const filter = {
      disponivel: true,
      quantidade: { $gt: 0 },
    };

    if (tipo && tipo !== "todos") {
      if (!TIPOS_MATERIAL.includes(tipo)) {
        return res.status(400).json({
          success: false,
          error: "Tipo de material inválido",
        });
      }
      filter.tipo = tipo;
    }

    if (precMax !== undefined && precMax !== "") {
      const value = Number(precMax);
      if (Number.isFinite(value)) {
        filter.preco = { $lte: value };
      }
    }

    if (qtdMin !== undefined && qtdMin !== "") {
      const value = Number(qtdMin);
      if (Number.isFinite(value)) {
        filter.quantidade = { $gte: value };
      }
    }

    let materials = await Material.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate(
        "userId",
        "email nomeCompleto nomeEmpresa nomeFantasia verificado empresaVerificada kgTotal notaMedia totalNegociacoes fotoPerfil"
      )
      .lean();

    if (q) {
      const search = String(q).toLowerCase();

      materials = materials.filter((item) => {
        const seller = item.userId || {};

        return (
          String(item.tipo || "").toLowerCase().includes(search) ||
          String(item.descricao || "").toLowerCase().includes(search) ||
          String(seller.email || "").toLowerCase().includes(search) ||
          String(seller.nomeCompleto || "").toLowerCase().includes(search) ||
          String(seller.nomeEmpresa || "").toLowerCase().includes(search)
        );
      });
    }

    const userLat = Number(lat);
    const userLon = Number(lon);
    const maxDistance = Number(raio);

    if (
      Number.isFinite(userLat) &&
      Number.isFinite(userLon) &&
      Number.isFinite(maxDistance)
    ) {
      materials = materials.filter((item) => {
        if (
          item.latitude === undefined ||
          item.longitude === undefined
        ) {
          return false;
        }

        const distance = calculateDistanceKm(
          userLat,
          userLon,
          item.latitude,
          item.longitude
        );

        return distance !== null && distance <= maxDistance;
      });
    }

    if (String(verificado).toLowerCase() === "true") {
      materials = materials.filter(
        (item) => item.userId?.verificado || item.userId?.empresaVerificada
      );
    }

    const total = await Material.countDocuments(filter);

    const responseMaterials = materials.map((item) => {
      const seller = item.userId || {};

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

        userId: seller._id,
        userEmail: seller.email,
        vendedorNome:
          seller.nomeEmpresa ||
          seller.nomeCompleto ||
          seller.nomeFantasia ||
          seller.email,

        vendedorVerificado: Boolean(seller.verificado),
        vendedorEmpresaVerificada: Boolean(seller.empresaVerificada),
        vendedorKgTotal: Number(seller.kgTotal || 0),
        vendedorNota: Number(seller.notaMedia || 0),
        vendedorNegociacoes: Number(seller.totalNegociacoes || 0),
      };
    });

    res.json({
      success: true,
      materials: responseMaterials,
      total,
      page,
      limit,
    });
  })
);

app.post(
  "/marketplace",
  auth,
  asyncRoute(async (req, res) => {
    const {
      tipo,
      quantidade,
      preco,
      precoNegociavel = true,
      descricao,
      fotoBase64,
      latitude,
      longitude,
    } = req.body;

    if (!TIPOS_MATERIAL.includes(tipo)) {
      return res.status(400).json({
        success: false,
        error: "Tipo de material inválido",
      });
    }

    const qtd = parsePositive(quantidade);
    const price = parsePositive(preco);

    if (!qtd) {
      return res.status(400).json({
        success: false,
        error: "Quantidade inválida",
      });
    }

    if (!price) {
      return res.status(400).json({
        success: false,
        error: "Preço inválido",
      });
    }

    if (qtd > 999999 || price > 99999) {
      return res.status(400).json({
        success: false,
        error: "Valor acima do limite permitido",
      });
    }

    if (String(descricao || "").length > 500) {
      return res.status(400).json({
        success: false,
        error: "Descrição muito longa",
      });
    }

    if (fotoBase64 && String(fotoBase64).length > 7 * 1024 * 1024) {
      return res.status(400).json({
        success: false,
        error: "Imagem muito grande",
      });
    }

    const material = await Material.create({
      tipo,
      quantidade: qtd,
      quantidadeInicial: qtd,
      preco: price,
      precoNegociavel: Boolean(precoNegociavel),
      descricao: sanitize(descricao),
      fotoBase64: String(fotoBase64 || ""),
      latitude:
        latitude !== undefined && Number.isFinite(Number(latitude))
          ? Number(latitude)
          : undefined,
      longitude:
        longitude !== undefined && Number.isFinite(Number(longitude))
          ? Number(longitude)
          : undefined,
      userId: req.user._id,
    });

    res.status(201).json({
      success: true,
      material,
    });
  })
);

// -----------------------------------------------------------------------------
// Purchase / negotiation
// -----------------------------------------------------------------------------

app.post(
  "/marketplace/buy",
  auth,
  asyncRoute(async (req, res) => {
    const {
      itemId,
      quantidade,
      formaPagamento = "dinheiro",
      precoProposto,
    } = req.body;

    if (!isValidObjectId(itemId)) {
      return res.status(400).json({
        success: false,
        error: "Anúncio inválido",
      });
    }

    if (!FORMAS_PAGAMENTO.includes(formaPagamento)) {
      return res.status(400).json({
        success: false,
        error: "Forma de pagamento inválida",
      });
    }

    const qtd = parsePositive(quantidade);

    if (!qtd) {
      return res.status(400).json({
        success: false,
        error: "Quantidade inválida",
      });
    }

    const material = await Material.findById(itemId);

    if (!material || !material.disponivel || material.quantidade <= 0) {
      return res.status(404).json({
        success: false,
        error: "Anúncio indisponível",
      });
    }

    if (material.userId.toString() === req.user._id.toString()) {
      return res.status(400).json({
        success: false,
        error: "Você não pode comprar seu próprio anúncio",
      });
    }

    if (qtd > material.quantidade) {
      return res.status(400).json({
        success: false,
        error: `Quantidade máxima disponível: ${material.quantidade}kg`,
      });
    }

    let effectivePrice = material.preco;
    let proposal = null;

    if (precoProposto !== undefined && precoProposto !== null) {
      if (!material.precoNegociavel) {
        return res.status(400).json({
          success: false,
          error: "Este anúncio não aceita propostas",
        });
      }

      proposal = parsePositive(precoProposto);

      if (!proposal) {
        return res.status(400).json({
          success: false,
          error: "Valor de proposta inválido",
        });
      }

      effectivePrice = proposal;
    }

    const valorTotal = Number((qtd * effectivePrice).toFixed(2));
    const taxaPlataforma = Number((valorTotal * 0.03).toFixed(2));

    // Reserva a quantidade no anúncio.
    material.quantidade = Number((material.quantidade - qtd).toFixed(3));

    if (material.quantidade <= 0) {
      material.quantidade = 0;
      material.disponivel = false;
    }

    await material.save();

    const negotiation = await Negotiation.create({
      materialId: material._id,
      vendedorId: material.userId,
      compradorId: req.user._id,
      vendedorEmail: null,
      compradorEmail: req.user.email,
      tipo: material.tipo,
      quantidade: qtd,
      precoPorKg: effectivePrice,
      valorTotal,
      taxaPlataforma,
      precoProposto: proposal,
      formaPagamento,
      status: "aguardando_pagamento",
    });

    const seller = await User.findById(material.userId);

    if (seller) {
      negotiation.vendedorEmail = seller.email;
      await negotiation.save();
    }

    res.status(201).json({
      success: true,
      negotiation,
      valor: valorTotal,
      taxa: taxaPlataforma,
      message:
        formaPagamento === "escrow"
          ? "Pagamento em escrow simulado. Aguardando confirmação da negociação."
          : "Negociação criada com sucesso.",
    });
  })
);

// -----------------------------------------------------------------------------
// Negotiations
// -----------------------------------------------------------------------------

app.get(
  "/negociacoes",
  auth,
  asyncRoute(async (req, res) => {
    const items = await Negotiation.find({
      $or: [
        { vendedorId: req.user._id },
        { compradorId: req.user._id },
      ],
    })
      .sort({ createdAt: -1 })
      .lean();

    const negotiations = items.map((item) => ({
      ...item,
      _id: item._id,
      vendedorId: String(item.vendedorId),
      compradorId: String(item.compradorId),
      vendedorEmail: item.vendedorEmail,
      compradorEmail: item.compradorEmail,
      avaliado: Boolean(item.avaliado),
    }));

    res.json({
      success: true,
      negociacoes: negotiations,
    });
  })
);

app.put(
  "/negociacoes/:id/status",
  auth,
  asyncRoute(async (req, res) => {
    const { status } = req.body;

    if (!STATUS_NEGOCIACAO.includes(status)) {
      return res.status(400).json({
        success: false,
        error: "Status inválido",
      });
    }

    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: "Negociação inválida",
      });
    }

    const negotiation = await Negotiation.findById(req.params.id);

    if (!negotiation) {
      return res.status(404).json({
        success: false,
        error: "Negociação não encontrada",
      });
    }

    const userId = req.user._id.toString();

    const isSeller = negotiation.vendedorId.toString() === userId;
    const isBuyer = negotiation.compradorId.toString() === userId;

    if (!isSeller && !isBuyer) {
      return res.status(403).json({
        success: false,
        error: "Você não participa desta negociação",
      });
    }

    // Vendedor controla a logística; comprador também pode finalizar
    // uma negociação em que participa.
    const allowedForBuyer = ["cancelado", "finalizado"];
    const allowedForSeller = [
      "pagamento_aprovado",
      "em_coleta",
      "em_transporte",
      "finalizado",
      "cancelado",
    ];

    if (isBuyer && !allowedForBuyer.includes(status)) {
      return res.status(403).json({
        success: false,
        error: "Ação não permitida para o comprador",
      });
    }

    if (isSeller && !allowedForSeller.includes(status)) {
      return res.status(403).json({
        success: false,
        error: "Ação não permitida para o vendedor",
      });
    }

    negotiation.status = status;
    await negotiation.save();

    // Ao finalizar, contabiliza o impacto uma única vez.
    if (status === "finalizado") {
      const alreadyFinalized = negotiation._finalizadoContabilizado;

      if (!alreadyFinalized) {
        await User.findByIdAndUpdate(negotiation.vendedorId, {
          $inc: {
            kgTotal: negotiation.quantidade,
            totalNegociacoes: 1,
          },
        });

        await User.findByIdAndUpdate(negotiation.compradorId, {
          $inc: {
            totalNegociacoes: 1,
          },
        });

        negotiation.set("_finalizadoContabilizado", true);
        await negotiation.save();
      }
    }

    res.json({
      success: true,
      negociacao: negotiation,
    });
  })
);

// -----------------------------------------------------------------------------
// Chats
// -----------------------------------------------------------------------------

app.get(
  "/chats",
  auth,
  asyncRoute(async (req, res) => {
    const chats = await Chat.find({
      participants: req.user._id,
    })
      .sort({ lastMessageAt: -1 })
      .populate(
        "participants",
        "_id email nomeCompleto nomeEmpresa fotoPerfil verificado"
      )
      .lean();

    const result = await Promise.all(
      chats.map(async (chat) => {
        const other = chat.participants.find(
          (p) => p._id.toString() !== req.user._id.toString()
        );

        const unread = 0; // contador pode ser implementado com readAt por mensagem.

        return {
          _id: chat._id,
          participants: chat.participants,
          lastMessagePreview: chat.lastMessage || "Iniciar conversa...",
          lastMessageAt: chat.lastMessageAt,
          naoLidas: unread,
          otherUser: other || null,
        };
      })
    );

    res.json({
      success: true,
      chats: result,
    });
  })
);

app.post(
  "/chats",
  auth,
  asyncRoute(async (req, res) => {
    const { otherUserId, marketplaceId } = req.body;

    if (!isValidObjectId(otherUserId)) {
      return res.status(400).json({
        success: false,
        error: "Usuário inválido",
      });
    }

    if (req.user._id.toString() === String(otherUserId)) {
      return res.status(400).json({
        success: false,
        error: "Você não pode conversar com você mesmo",
      });
    }

    const other = await User.findById(otherUserId);

    if (!other) {
      return res.status(404).json({
        success: false,
        error: "Usuário não encontrado",
      });
    }

    const participants = [req.user._id, other._id];

    let chat = await Chat.findOne({
      participants: { $all: participants, $size: 2 },
      ...(isValidObjectId(marketplaceId)
        ? { marketplaceId }
        : {}),
    });

    if (!chat) {
      chat = await Chat.create({
        participants,
        marketplaceId:
          isValidObjectId(marketplaceId) ? marketplaceId : null,
      });
    }

    res.json({
      success: true,
      chatId: chat._id,
      chat,
    });
  })
);

app.get(
  "/messages/:chatId",
  auth,
  asyncRoute(async (req, res) => {
    if (!isValidObjectId(req.params.chatId)) {
      return res.status(400).json({
        success: false,
        error: "Chat inválido",
      });
    }

    const chat = await Chat.findOne({
      _id: req.params.chatId,
      participants: req.user._id,
    });

    if (!chat) {
      return res.status(403).json({
        success: false,
        error: "Acesso negado",
      });
    }

    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 10));

    const messages = await Message.find({
      chatId: chat._id,
    })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate("senderId", "_id email nomeCompleto nomeEmpresa")
      .lean();

    res.json({
      success: true,
      messages,
      page,
      limit,
    });
  })
);

app.post(
  "/messages",
  auth,
  asyncRoute(async (req, res) => {
    const { chatId, text } = req.body;

    if (!isValidObjectId(chatId)) {
      return res.status(400).json({
        success: false,
        error: "Chat inválido",
      });
    }

    const cleanText = sanitize(text);

    if (!cleanText) {
      return res.status(400).json({
        success: false,
        error: "Mensagem vazia",
      });
    }

    if (cleanText.length > 1000) {
      return res.status(400).json({
        success: false,
        error: "Mensagem muito longa",
      });
    }

    const chat = await Chat.findOne({
      _id: chatId,
      participants: req.user._id,
    });

    if (!chat) {
      return res.status(403).json({
        success: false,
        error: "Chat não encontrado ou acesso negado",
      });
    }

    const message = await Message.create({
      chatId,
      senderId: req.user._id,
      text: cleanText,
    });

    chat.lastMessage = cleanText;
    chat.lastMessageAt = new Date();
    await chat.save();

    const populated = await Message.findById(message._id)
      .populate("senderId", "_id email nomeCompleto nomeEmpresa")
      .lean();

    res.status(201).json({
      success: true,
      message: populated,
    });
  })
);

// -----------------------------------------------------------------------------
// Reviews
// -----------------------------------------------------------------------------

app.post(
  "/avaliacoes",
  auth,
  asyncRoute(async (req, res) => {
    const { negociacaoId, vendedorId, nota, comentario } = req.body;

    if (
      !isValidObjectId(negociacaoId) ||
      !isValidObjectId(vendedorId)
    ) {
      return res.status(400).json({
        success: false,
        error: "Dados da avaliação inválidos",
      });
    }

    const rating = Number(nota);

    if (!Number.isFinite(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({
        success: false,
        error: "Nota deve estar entre 1 e 5",
      });
    }

    const cleanComment = sanitize(comentario);

    if (!cleanComment) {
      return res.status(400).json({
        success: false,
        error: "Comentário obrigatório",
      });
    }

    const negotiation = await Negotiation.findById(negociacaoId);

    if (!negotiation) {
      return res.status(404).json({
        success: false,
        error: "Negociação não encontrada",
      });
    }

    if (negotiation.status !== "finalizado") {
      return res.status(400).json({
        success: false,
        error: "A negociação ainda não foi finalizada",
      });
    }

    if (
      negotiation.compradorId.toString() !== req.user._id.toString() ||
      negotiation.vendedorId.toString() !== vendedorId
    ) {
      return res.status(403).json({
        success: false,
        error: "Você não pode avaliar esta negociação",
      });
    }

    const already = await Review.findOne({
      negociacaoId,
      autorId: req.user._id,
    });

    if (already) {
      return res.status(409).json({
        success: false,
        error: "Você já avaliou esta negociação",
      });
    }

    const review = await Review.create({
      negociacaoId,
      vendedorId,
      autorId: req.user._id,
      nota: rating,
      comentario: cleanComment,
    });

    const stats = await Review.aggregate([
      {
        $match: {
          vendedorId: new mongoose.Types.ObjectId(vendedorId),
        },
      },
      {
        $group: {
          _id: "$vendedorId",
          media: { $avg: "$nota" },
        },
      },
    ]);

    const average = stats[0]?.media || rating;

    await User.findByIdAndUpdate(vendedorId, {
      $set: { notaMedia: Number(average.toFixed(2)) },
    });

    negotiation.avaliado = true;
    await negotiation.save();

    res.status(201).json({
      success: true,
      review,
    });
  })
);

app.get(
  "/user/:id/reviews",
  auth,
  asyncRoute(async (req, res) => {
    if (!isValidObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        error: "Usuário inválido",
      });
    }

    const reviews = await Review.find({
      vendedorId: req.params.id,
    })
      .sort({ createdAt: -1 })
      .limit(50)
      .populate("autorId", "email nomeCompleto nomeEmpresa")
      .lean();

    res.json({
      success: true,
      reviews: reviews.map((review) => ({
        ...review,
        autorEmail:
          review.autorId?.email || "Usuário",
      })),
    });
  })
);

// -----------------------------------------------------------------------------
// Complaints
// -----------------------------------------------------------------------------

app.post(
  "/denuncias",
  auth,
  asyncRoute(async (req, res) => {
    const { tipo, alvoId, motivo, detalhe } = req.body;

    if (!["usuario", "anuncio"].includes(tipo)) {
      return res.status(400).json({
        success: false,
        error: "Tipo de denúncia inválido",
      });
    }

    if (!isValidObjectId(alvoId)) {
      return res.status(400).json({
        success: false,
        error: "Alvo inválido",
      });
    }

    if (!MOTIVOS_DENUNCIA.includes(motivo)) {
      return res.status(400).json({
        success: false,
        error: "Motivo inválido",
      });
    }

    const detail = sanitize(detalhe);

    if (!detail) {
      return res.status(400).json({
        success: false,
        error: "Detalhe obrigatório",
      });
    }

    const complaint = await Complaint.create({
      tipo,
      alvoId,
      autorId: req.user._id,
      motivo,
      detalhe: detail,
    });

    res.status(201).json({
      success: true,
      denuncia: complaint,
    });
  })
);

// -----------------------------------------------------------------------------
// ESG dashboard
// -----------------------------------------------------------------------------

app.get(
  "/esg/dashboard",
  auth,
  asyncRoute(async (req, res) => {
    const [userStats, materialStats, usersActive, negotiationCount] =
      await Promise.all([
        User.aggregate([
          {
            $group: {
              _id: null,
              totalKg: { $sum: "$kgTotal" },
            },
          },
        ]),
        Negotiation.aggregate([
          {
            $match: { status: "finalizado" },
          },
          {
            $group: {
              _id: "$tipo",
              kg: { $sum: "$quantidade" },
            },
          },
        ]),
        User.countDocuments({ totalNegociacoes: { $gt: 0 } }),
        Negotiation.countDocuments({ status: "finalizado" }),
      ]);

    const totalKg = Number(userStats[0]?.totalKg || 0);
    const materiais = {};

    for (const item of materialStats) {
      materiais[item._id] = Number(item.kg || 0);
    }

    res.json({
      success: true,
      dados: {
        totalKg,
        co2Evitado: Number((totalKg * 2.5).toFixed(1)),
        usuariosAtivos: usersActive,
        negociacoes: negotiationCount,
        materiais,
      },
    });
  })
);

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Rota não encontrada",
    path: req.originalUrl,
  });
});

app.use((err, req, res, next) => {
  console.error("❌ API Error:", err);

  if (err?.code === 11000) {
    return res.status(409).json({
      success: false,
      error: "Registro duplicado",
    });
  }

  if (err instanceof mongoose.Error.ValidationError) {
    return res.status(400).json({
      success: false,
      error: Object.values(err.errors)
        .map((e) => e.message)
        .join(", "),
    });
  }

  res.status(500).json({
    success: false,
    error: "Erro interno do servidor",
  });
});

// -----------------------------------------------------------------------------
// Database + server
// -----------------------------------------------------------------------------

async function start() {
  try {
    if (!MONGODB_URI) {
      throw new Error(
        "Configure MONGODB_URI (ou MONGO_URI) no arquivo .env"
      );
    }

    await mongoose.connect(MONGODB_URI);

    console.log("✅ MongoDB conectado");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`🚀 ReciTech API rodando na porta ${PORT}`);
      console.log(`🌐 http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("❌ Falha ao iniciar API:", error.message);
    process.exit(1);
  }
}

start();

module.exports = app;

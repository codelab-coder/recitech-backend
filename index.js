// index.js — Backend ReciTech V2 (ATUALIZADO 100% com Nelson Nishiwaki - Dez/2025)
// COPIE E COLE TUDO NO SEU ARQUIVO PRINCIPAL (Render.com)
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "recitech_secret_2025";

// TAXA DA PLATAFORMA (10% = usuário recebe 90%)
const TAXA_PLATAFORMA = 0.10;

// PREÇOS POR KG (média de mercado Brasil 2025 - ajustável)
const PRECOS_POR_KG = {
  plástico: 2.8,
  pet: 3.5,
  papel: 1.2,
  papelão: 1.0,
  metal: 4.5,
  alumínio: 6.8,
  vidro: 0.8,
  orgânico: 0.3,
  eletrônico: 15.0,
  bateria: 20.0,
  óleo: 5.0,
  desconhecido: 0.5,
};

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// ====================== SCHEMAS ======================
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  cnpj: { type: String, unique: true, sparse: true },

  // === NOVO: Carteira e Impacto ===
  saldo: { type: Number, default: 0 }, // saldo em reais
  totalKg: { type: Number, default: 0 },
  totalCo2: { type: Number, default: 0 }, // toneladas evitadas (kg * 2.1)
  rank: { type: String, default: "Bronze" },
  badges: { type: [String], default: ["primeira"] },
  historicoMensal: { type: [Number], default: [0,0,0,0,0,0] }, // últimos 6 meses
});

const User = mongoose.model("User", UserSchema);

const MaterialSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, default: "desconhecido" },
  estimatedKg: { type: Number, default: 0.5 },
  value: { type: Number, default: 0 }, // valor creditado
  confidence: { type: Number, default: 0 },
  photoBase64: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Material = mongoose.model("Material", MaterialSchema);

// ====================== MIDDLEWARE ======================
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "Token ausente" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, error: "Token inválido" });
  }
};

const upload = multer();

// ====================== FUNÇÕES AUXILIARES ======================
const atualizarRank = (totalKg) => {
  if (totalKg >= 500) return "Diamante";
  if (totalKg >= 300) return "Ouro";
  if (totalKg >= 100) return "Prata";
  if (totalKg >= 50) return "Bronze";
  return "Iniciante";
};

const creditarUsuario = async (userId, tipo, kg) => {
  const preco = PRECOS_POR_KG[tipo] || 1.5;
  const valor = kg * preco;
  const co2Evitado = kg * 2.1; // média realista

  await User.findByIdAndUpdate(userId, {
    $inc: {
      saldo: valor,
      totalKg: kg,
      totalCo2: co2Evitado,
    },
    $push: { historicoMensal: { $each: [kg], $slice: -6 } }, // últimos 6 meses
  });

  const user = await User.findById(userId);
  const novoRank = atualizarRank(user.totalKg);
  if (user.rank !== novoRank) {
    await User.findByIdAndUpdate(userId, { rank: novoRank });
  }

  // Badges automáticas
  const badgesAtuais = user.badges || [];
  if (user.totalKg > 50 && !badgesAtuais.includes("50kg")) badgesAtuais.push("50kg");
  if (user.totalKg > 100 && !badgesAtuais.includes("100kg")) badgesAtuais.push("100kg");
  await User.findByIdAndUpdate(userId, { badges: badgesAtuais });
};

// ====================== ROTAS ======================

// CADASTRO
app.post("/register", async (req, res) => {
  try {
    const { email, password, cnpj } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: "Email e senha obrigatórios" });

    const jaExiste = await User.findOne({ email: email.toLowerCase() });
    if (jaExiste) return res.status(400).json({ success: false, error: "Email já cadastrado" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      email: email.toLowerCase(),
      password: hashed,
      cnpj: cnpj || undefined,
    });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, accessToken: token, message: "Conta criada!" });
  } catch (e) {
    console.error("Erro cadastro:", e);
    res.status(500).json({ success: false, error: "Erro no servidor" });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ success: false, error: "Credenciais inválidas" });
    }
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, accessToken: token });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro no servidor" });
  }
});

// PERFIL DO USUÁRIO (carteira + impacto)
app.get("/user/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ success: false, error: "Usuário não encontrado" });

    res.json({
      success: true,
      user: {
        saldo: Number(user.saldo.toFixed(2)),
        totalKg: Number(user.totalKg.toFixed(2)),
        totalCo2: Number(user.totalCo2.toFixed(2)),
        rank: user.rank,
        badges: user.badges,
        historicoMensal: user.historicoMensal,
      },
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao carregar perfil" });
  }
});

// UPLOAD DE FOTO + CRÉDITO AUTOMÁTICO
app.post("/materials", auth, upload.none(), async (req, res) => {
  try {
    let photoBase64 = (req.body.photoBase64 || "").trim();
    photoBase64 = photoBase64.replace(/^data:image\/[a-zA-Z+\/]+;base64,/, "");

    if (!photoBase64 || photoBase64.length < 8000) {
      return res.status(400).json({ success: false, error: "Imagem inválida" });
    }

    // Simulação de IA (substitua por sua IA real depois)
    const tiposPossiveis = ["plástico", "papel", "metal", "vidro", "eletrônico", "orgânico", "pet", "alumínio"];
    const tipo = tiposPossiveis[Math.floor(Math.random() * tiposPossiveis.length)];
    const estimatedKg = parseFloat((Math.random() * 1.5 + 0.3).toFixed(2)); // 0.3 a 1.8kg
    const confidence = parseFloat((Math.random() * 0.3 + 0.7).toFixed(2)); // 70-99%

    const valor = estimatedKg * (PRECOS_POR_KG[tipo] || 1.5);

    const material = await Material.create({
      userId: req.user.id,
      type: tipo,
      estimatedKg,
      value: Number(valor.toFixed(2)),
      confidence,
      photoBase64,
    });

    // CREDITAR NA CARTEIRA
    await creditarUsuario(req.user.id, tipo, estimatedKg);

    res.json({
      success: true,
      type: tipo,
      estimatedKg,
      value: Number(valor.toFixed(2)),
      confidence,
      message: "Reciclagem registrada e crédito adicionado!",
    });
  } catch (e) {
    console.error("ERRO UPLOAD:", e);
    res.status(500).json({ success: false, error: "Erro ao processar" });
  }
});

// LISTAR MATERIAIS DO USUÁRIO
app.get("/materials", auth, async (req, res) => {
  try {
    const materials = await Material.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json({ success: true, materials });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao listar" });
  }
});

// PAGAMENTO (RESGATE PIX) - MOBILE
app.post("/create-payment-intent", auth, async (req, res) => {
  try {
    const { amount } = req.body; // em centavos
    const user = await User.findById(req.user.id);

    if (!user || user.saldo < amount / 100) {
      return res.status(400).json({ success: false, error: "Saldo insuficiente" });
    }

    const taxa = Math.round(amount * TAXA_PLATAFORMA);
    const liquido = amount - taxa;

    // Aqui você conecta com Stripe, PagSeguro, Mercado Pago, etc.
    // Por enquanto simulamos sucesso
    await User.findByIdAndUpdate(req.user.id, {
      $inc: { saldo: -amount / 100 },
    });

    res.json({
      clientSecret: `pi_simulado_${Date.now()}`,
      amountLiquido: liquido,
      taxa,
      mensagem: "Resgate aprovado! Valor cai em até 48h via PIX.",
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro no resgate" });
  }
});

// PAGAMENTO WEB (CHECKOUT)
app.post("/create-checkout-session", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);

    if (!user || user.saldo < amount / 100) {
      return res.status(400).json({ success: false, error: "Saldo insuficiente" });
    }

    const taxa = Math.round(amount * TAXA_PLATAFORMA);
    const liquido = amount - taxa;

    // Simulação de sessão Stripe
    await User.findByIdAndUpdate(req.user.id, {
      $inc: { saldo: -amount / 100 },
    });

    res.json({
      sessionId: `cs_simulado_${Date.now()}`,
      amountLiquido: liquido,
      taxa,
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro no checkout" });
  }
});

// ====================== START ======================
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("MongoDB conectado com sucesso!");
    console.log(`Taxa da plataforma: ${(TAXA_PLATAFORMA * 100)}%`);
    console.log(`Backend rodando na porta ${PORT}`);
    console.log(`URL: https://recitech-backend.onrender.com`);
  })
  .catch(err => {
    console.error("Erro MongoDB:", err);
    process.exit(1);
  });

app.listen(PORT, "0.0.0.0");

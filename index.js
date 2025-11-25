// index.js — Backend ReciTech FINAL 2025 (Render.com)
// COPIE E COLE TUDO NO SEU ARQUIVO PRINCIPAL

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

// TAXA DA PLATAFORMA (mude aqui se quiser 8%, 12%, etc)
const TAXA_PLATAFORMA = 0.10; // 10% → usuário recebe 90%

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// ====================== SCHEMAS ======================
const User = mongoose.model("User", new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  cnpj: { type: String, unique: true, sparse: true },
}));

const Material = mongoose.model("Material", new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, default: "desconhecido" },
  quantity: { type: Number, default: 1 },
  pricePerKg: { type: Number, default: 0 },
  photoBase64: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
}));

const HubMaterial = mongoose.model("HubMaterial", new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name: { type: String, required: true },
  qty: { type: Number, required: true },
  price: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
}));

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

// ====================== ROTAS ======================

// CADASTRO
app.post("/register", async (req, res) => {
  try {
    const { email, password, cnpj } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, error: "Email e senha obrigatórios" });

    const jaExiste = await User.findOne({
      $or: [{ email: email.toLowerCase() }, cnpj ? { cnpj } : null].filter(Boolean)
    });
    if (jaExiste) return res.status(400).json({ success: false, error: "Email ou CNPJ já cadastrado" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      email: email.toLowerCase(),
      password: hashed,
      cnpj: cnpj || undefined,
    });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, accessToken: token, message: "Conta criada com sucesso!" });
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
    console.error("Erro login:", e);
    res.status(500).json({ success: false, error: "Erro no servidor" });
  }
});

// UPLOAD DE FOTO
app.post("/materials", auth, upload.none(), async (req, res) => {
  try {
    let photoBase64 = (req.body.photoBase64 || "").trim();
    photoBase64 = photoBase64.replace(/^data:image\/[a-zA-Z+\/]+;base64,/, "");

    if (!photoBase64 || photoBase64.length < 8000) {
      return res.status(400).json({ success: false, error: "Imagem inválida ou muito pequena" });
    }

    await Material.create({
      userId: req.user.id,
      photoBase64,
      type: req.body.type || "processando",
    });

    res.json({ success: true });
  } catch (e) {
    console.error("ERRO UPLOAD:", e.message);
    res.status(500).json({ success: false, error: "Erro ao salvar foto" });
  }
});

// LISTAR FOTOS DO USUÁRIO
app.get("/materials", auth, async (req, res) => {
  try {
    const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json({ success: true, materials });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao listar" });
  }
});

// HUB FINANCEIRO - LISTAR
app.get("/hub-materials", auth, async (req, res) => {
  try {
    const materials = await HubMaterial.find({ userId: req.user.id }).sort({ createdAt: -1 });
    const totalBruto = materials.reduce((acc, m) => acc + m.qty * m.price, 0);
    const taxa = totalBruto * TAXA_PLATAFORMA;
    const totalLiquido = totalBruto - taxa;

    res.json({
      success: true,
      materials,
      totalBruto: Number(totalBruto.toFixed(2)),
      taxa: Number(taxa.toFixed(2)),
      totalLiquido: Number(totalLiquido.toFixed(2)),
      taxaPercentual: (TAXA_PLATAFORMA * 100) + "%"
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao carregar hub" });
  }
});

// HUB FINANCEIRO - ADICIONAR
app.post("/hub-materials", auth, async (req, res) => {
  try {
    const { name, qty, price } = req.body;
    if (!name || !qty || !price) return res.status(400).json({ success: false, error: "Preencha todos os campos" });

    const material = await HubMaterial.create({
      userId: req.user.id,
      name: name.trim(),
      qty: Number(qty),
      price: Number(price),
    });

    res.json({ success: true, material });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao adicionar" });
  }
});

// LIMPAR HUB APÓS PAGAMENTO
app.delete("/hub-materials", auth, async (req, res) => {
  try {
    await HubMaterial.deleteMany({ userId: req.user.id });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao limpar" });
  }
});

// PAGAMENTO MOBILE (com taxa)
app.post("/create-payment-intent", auth, async (req, res) => {
  try {
    const { amount } = req.body; // valor bruto em centavos
    const taxa = Math.round(amount * TAXA_PLATAFORMA);
    const amountLiquido = amount - taxa;

    // AQUI VOCÊ VAI COLOCAR O STRIPE DE VERDADE DEPOIS
    res.json({
      clientSecret: `pi_test_${Date.now()}_secret_${amountLiquido}`,
      amountLiquido,
      taxa,
      mensagem: `Você receberá R$ ${(amountLiquido / 100).toFixed(2)} após taxa de ${TAXA_PLATAFORMA * 100}%`
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro no pagamento" });
  }
});

// PAGAMENTO WEB (com taxa)
app.post("/create-checkout-session", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    const taxa = Math.round(amount * TAXA_PLATAFORMA);
    const amountLiquido = amount - taxa;

    // AQUI VOCÊ VAI COLOCAR O STRIPE CHECKOUT DEPOIS
    res.json({
      sessionId: `cs_test_${Date.now()}_${amountLiquido}`,
      amountLiquido,
      taxa
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro no checkout" });
  }
});

// ====================== START ======================
mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB conectado com sucesso!"))
  .catch(err => {
    console.error("Erro MongoDB:", err);
    process.exit(1);
  });

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend rodando na porta ${PORT}`);
  console.log(`Taxa da plataforma: ${(TAXA_PLATAFORMA * 100)}%`);
  console.log(`URL: https://recitech-backend.onrender.com`);
});

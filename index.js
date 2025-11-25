// index.js — Backend ReciTech (Render.com) — VERSÃO FINAL 2025 COM TAXA + HUB FINANCEIRO
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

// Materiais do upload (fotos)
const Material = mongoose.model("Material", new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, default: "desconhecido" },
  quantity: { type: Number, default: 1 },
  pricePerKg: { type: Number, default: 0 },
  photoBase64: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
}));

// Materiais do Hub Financeiro (lista de valores a receber)
const HubMaterial = mongoose.model("HubMaterial", new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name: { type: String, required: true },
  qty: { type: Number, required: true },
  price: { type: Number, required: true }, // preço por kg
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

// Upload de foto (mantido como estava)
app.post("/materials", auth, upload.none(), async (req, res) => {
  try {
    let photoBase64 = (req.body.photoBase64 || "").trim();
    photoBase64 = photoBase64.replace(/^data:image\/[a-zA-Z]+;base64,/, "");

    if (!photoBase64 || photoBase64.length < 8000) {
      return res.status(400).json({ success: false, error: "Imagem inválida" });
    }

    await Material.create({
      userId: req.user.id,
      type: req.body.type || "plastico",
      quantity: Number(req.body.quantity) || 1,
      pricePerKg: Number(req.body.pricePerKg) || 0,
      photoBase64,
    });

    res.json({ success: true });
  } catch (e) {
    console.error("ERRO UPLOAD:", e.message);
    res.status(500).json({ success: false, error: "Erro ao salvar" });
  }
});

// Listar fotos do usuário (só as dele)
app.get("/materials", auth, async (req, res) => {
  try {
    const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json({ success: true, materials });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao listar" });
  }
});

// ====================== HUB FINANCEIRO ======================

// Pegar materiais do hub (só do usuário logado)
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
      taxaPercentual: TAXA_PLATAFORMA * 100 + "%"
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao carregar hub" });
  }
});

// Adicionar material no hub
app.post("/hub-materials", auth, async (req, res) => {
  try {
    const { name, qty, price } = req.body;
    if (!name || !qty || !price) return res.status(400).json({ success: false, error: "Dados incompletos" });

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

// Limpar o hub após pagamento (opcional — você pode chamar depois do sucesso)
app.delete("/hub-materials", auth, async (req, res) => {
  try {
    await HubMaterial.deleteMany({ userId: req.user.id });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao limpar" });
  }
});

// ====================== PAGAMENTOS (com taxa) ======================

// Payment Intent (mobile) — já desconta a taxa
app.post("/create-payment-intent", auth, async (req, res) => {
  try {
    const { amount } = req.body; // valor bruto
    const taxa = amount * TAXA_PLATAFORMA;
    const amountLiquido = Math.round(amount - taxa);

    res.json({
      clientSecret: `pi_fake_${Date.now()}_secret_${amountLiquido}`, // substitua pelo Stripe real
      amountLiquido,
      taxa: Math.round(taxa),
      mensagem: `Você receberá R$ ${(amountLiquido / 100).toFixed(2)} (após taxa de ${TAXA_PLATAFORMA * 100}%)`
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro no pagamento" });
  }
});

// Checkout Session (web) — já desconta a taxa
app.post("/create-checkout-session", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    const taxa = amount * TAXA_PLATAFORMA;
    const amountLiquido = Math.round(amount - taxa);

    res.json({
      sessionId: `cs_fake_${Date.now()}_${amountLiquido}`, // substitua pelo Stripe real
      amountLiquido,
      taxa: Math.round(taxa)
    });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro no checkout" });
  }
});

// ====================== LOGIN ======================
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

// ====================== START ======================
mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB conectado!"))
  .catch(err => {
    console.error("Erro MongoDB:", err);
    process.exit(1);
  });

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend rodando na porta ${PORT}`);
  console.log(`Taxa da plataforma: ${(TAXA_PLATAFORMA * 100)}%`);
});

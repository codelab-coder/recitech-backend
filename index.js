// index.js — VERSÃO FINAL 100% FUNCIONANDO NO RENDER (21/11/2025)

import express from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import multer from "multer";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "recitech_secret_fallback_2025";

// Middlewares
app.use(cors());
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true })); // OBRIGATÓRIO pro upload do Expo

app.use(rateLimit({
  windowMs: 60_limit: 100,
  message: { success: false, error: "Muitas requisições, calma aí!" }
}));

// MongoDB
try {
  await mongoose.connect(MONGO_URI);
  console.log("MongoDB conectado com sucesso!");
} catch (err) {
  console.error("Erro ao conectar MongoDB:", err);
  process.exit(1);
}

// Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  cnpj: { type: String, unique: true, sparse: true },
});

const materialSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  type: { type: String, default: "desconhecido" },
  quantity: { type: Number, default: 1 },
  pricePerKg: { type: Number, default: 0 },
  photoBase64: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);

// JWT Auth
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

// Multer
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024 }, // 12MB
});

// Rotas
app.get("/", (req, res) => {
  res.json({ success: true, message: "ReciTech Backend rodando com Node 22!" });
});

app.post("/register", async (req, res) => {
  try {
    const { email, password, cnpj } = req.body;
    if (!email || !password || !cnpj) {
      return res.status(400).json({ success: false, error: "Preencha todos os campos" });
    }

    const exists = await User.findOne({ $or: [{ email }, { cnpj }] });
    if (exists) return res.status(400).json({ success: false, error: "Email ou CNPJ já cadastrado" });

    const hashed = await bcrypt.hash(password, 12);
    await User.create({ email: email.toLowerCase(), password: hashed, cnpj });

    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Erro no servidor" });
  }
});

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
    res.status(500).json({ success: false, error: "Erro no login" });
  }
});

// UPLOAD — ACEITA FileSystem.uploadAsync + fallback base64
app.post("/materials", auth, upload.single("photo"), async (req, res) => {
  try {
    let photoBase64 = "";
    let type = "desconhecido";
    let quantity = 1;
    let pricePerKg = 0;

    // 1. Arquivo enviado pelo Expo (FileSystem.uploadAsync)
    if (req.file) {
      photoBase64 = req.file.buffer.toString("base64");
      type = req.body.type || type;
      quantity = Number(req.body.quantity) || 1;
      pricePerKg = Number(req.body.pricePerKg) || 0;
    }
    // 2. Fallback: JSON com photoBase64
    else if (req.body.photoBase64) {
      photoBase64 = req.body.photoBase64.replace(/^data:image\/\w+;base64,/, "");
      type = req.body.type || type;
      quantity = Number(req.body.quantity) || 1;
      pricePerKg = Number(req.body.pricePerKg) || 0;
    } else {
      return res.status(400).json({ success: false, error: "Imagem ausente" });
    }

    await Material.create({
      userId: req.user.id,
      type,
      quantity,
      pricePerKg,
      photoBase64,
    });

    res.json({ success: true });
  } catch (e) {
    console.error("Erro upload:", e);
    res.status(500).json({ success: false, error: "Erro ao salvar material" });
  }
});

// Lista materiais
app.get("/materials", auth, async (req, res) => {
  try {
    const materials = await Material.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .lean();
    res.json({ success: true, materials });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro ao listar" });
  }
});

// Inicia servidor
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Acesse: https://recitech-backend.onrender.com`);
});

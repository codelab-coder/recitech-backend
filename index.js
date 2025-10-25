import axios from "axios";
import bodyParser from "body-parser";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";

// ============================================================
// 1. CONFIGURAÇÕES GERAIS
// ============================================================
const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/recitech";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey_dev_only";
const IA_API_URL = process.env.IA_API_URL || "https://recitech-ia-api.onrender.com";

// ============================================================
// 2. CORS ROBUSTO (Netlify + Localhost)
// ============================================================
const ALLOWED_ORIGINS = [
  "https://recitech.netlify.app",
  "https://recitech-mvp.netlify.app",
  "http://localhost:19006",
  "http://localhost:3000"
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Acesso não permitido pelo CORS"));
    }
  },
  credentials: true,
};

app.use(cors(corsOptions));

// ============================================================
// 3. SEGURANÇA E LIMITE DE REQUISIÇÕES
// ============================================================
app.use(helmet());
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ============================================================
// 4. BODY PARSER COM LIMITE SEGURO (50MB) + LOGS
// ============================================================
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ============================================================
// 5. MONGODB SCHEMAS
// ============================================================
const userSchema = new mongoose.Schema({
  email: String,
  password: String, // ⚠️ Em produção use bcrypt
  cnpj: String
});

const materialSchema = new mongoose.Schema({
  userId: mongoose.Types.ObjectId,
  type: String,
  quantity: Number,
  pricePerKg: Number,
  photoBase64: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);

// ============================================================
// 6. CONEXÃO AO MONGO
// ============================================================
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB conectado"))
  .catch(err => console.error("❌ Erro MongoDB:", err));

// ============================================================
// 7. MIDDLEWARE DE AUTENTICAÇÃO (JWT)
// ============================================================
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, error: "Token ausente" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, error: "Token inválido" });
  }
};

// ============================================================
// 8. ROTAS DE AUTENTICAÇÃO
// ============================================================
app.get("/", (req, res) => res.json({ success: true, msg: "Backend ReciTech online" }));

app.post("/register", async (req, res) => {
  const { email, password, cnpj } = req.body;
  if (!email || !password || !cnpj)
    return res.json({ success: false, error: "Campos obrigatórios" });

  const exists = await User.findOne({ email });
  if (exists) return res.json({ success: false, error: "Email já cadastrado" });

  const user = new User({ email, password, cnpj });
  await user.save();
  res.json({ success: true });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.json({ success: false, error: "Campos obrigatórios" });

  const user = await User.findOne({ email, password });
  if (!user) return res.json({ success: false, error: "Credenciais inválidas" });

  const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, accessToken: token });
});

// ============================================================
// 9. ROTAS DE MATERIAIS (UPLOAD + LISTAGEM)
// ============================================================
const MAX_BYTES = 50 * 1024 * 1024;
const MAX_BASE64_CHARS = Math.ceil((MAX_BYTES * 4) / 3);

app.post("/materials", authMiddleware, async (req, res) => {
  try {
    const { type, quantity, pricePerKg, photoBase64 } = req.body;
    if (!photoBase64) return res.status(400).json({ success: false, error: "Imagem ausente" });

    const cleanBase64 = photoBase64.includes(",") ? photoBase64.split(",")[1] : photoBase64;

    if (cleanBase64.length > MAX_BASE64_CHARS) {
      return res.status(413).json({
        success: false,
        error: `Imagem muito grande. Máximo permitido: ${Math.round(MAX_BYTES / 1024 / 1024)} MB.`
      });
    }

    const material = new Material({
      userId: req.user.id,
      type: type || "desconhecido",
      quantity: quantity || 1,
      pricePerKg: pricePerKg || 0,
      photoBase64: cleanBase64
    });

    await material.save();
    console.log(`📸 Upload OK: ${material.type} (${cleanBase64.length} chars)`);
    res.json({ success: true, material });

  } catch (err) {
    console.error("❌ Erro no upload:", err);
    res.status(500).json({ success: false, error: "Erro interno no upload" });
  }
});

app.get("/materials", authMiddleware, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

// ============================================================
// 🔹 10. PROXY PARA A IA FASTAPI
// ============================================================
const cache = new Map(); // cache simples de classificação

app.post("/classify", authMiddleware, async (req, res) => {
  const { photoBase64 } = req.body;
  if (!photoBase64) return res.json({ success: false, error: "Imagem ausente" });

  const hash = crypto.createHash("sha256").update(photoBase64).digest("hex");
  if (cache.has(hash)) return res.json(cache.get(hash));

  try {
    const response = await axios.post(`${IA_API_URL}/classify`, { photoBase64 });
    cache.set(hash, response.data);
    res.json(response.data);
  } catch (err) {
    console.error("Erro na classificação da IA:", err.message);
    res.status(503).json({ success: false, error: "Serviço de IA temporariamente indisponível." });
  }
});

// ============================================================
// 11. INICIAR SERVIDOR
// ============================================================
app.listen(PORT, () =>
  console.log(`✅ Backend rodando em http://0.0.0.0:${PORT}`)
);

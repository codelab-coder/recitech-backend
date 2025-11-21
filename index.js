// index.js — 100% compatível com Render + Node.js 22 + ESM
import express from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import multer from "multer";
import bcrypt from "bcryptjs";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_dev_123";

// Middlewares
app.use(cors());
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true })); // ESSENCIAL

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: { success: false, error: "Muitas requisições" },
  })
);

// MongoDB
await mongoose.connect(MONGO_URI);
console.log("MongoDB conectado com sucesso!");

// Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  cnpj: { type: String, unique: true, sparse: true },
});

const materialSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  type: String,
  quantity: Number,
  pricePerKg: Number,
  photoBase64: String,
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Material = mongoose.model("Material", materialSchema);

// JWT Middleware
const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer "))
    return res.status(401).json({ success: false, error: "Token ausente" });

  try {
    const token = authHeader.split(" ")[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, error: "Token inválido" });
  }
};

// Multer
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// Rotas
app.get("/", (req, res) => {
  res.json({ success: true, msg: "ReciTech Backend ONLINE" });
});

app.post("/register", async (req, res) => {
  try {
    const { email, password, cnpj } = req.body;
    if (!email || !password || !cnpj)
      return res.status(400).json({ success: false, error: "Todos os campos" });

    if (await User.findOne({ $or: [{ email }, { cnpj }] }))
      return res.status(400).json({ success: false, error: "Email ou CNPJ já existe" });

    const hashed = await bcrypt.hash(password, 12);
    await User.create({ email, password: hashed, cnpj });

    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: "Erro no servidor" });
  }
});

app.post("/login", async (req, res) => {
  {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ success: false, error: "Credenciais inválidas" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, accessToken: token });
  } catch (e) {
    res.status(500).json({ success: false, error: "Erro no login" });
  }
});

app.post("/materials", auth, upload.single("photo"), async (req, res) => {
  try {
    let photoBase64 = "";
    let type = "desconhecido";
    let quantity = 1;
    let pricePerKg = 0;

    if (req.file) {
      photoBase64 = req.file.buffer.toString("base64");
      type = req.body.type || type;
      quantity = Number(req.body.quantity) || quantity;
      pricePerKg = Number(req.body.pricePerKg) || pricePerKg;
    } else if (req.body.photoBase64) {
      photoBase64 = req.body.photoBase64.replace(/^data:image\/\w+;base64,/, "");
      type = req.body.type || type;
      quantity = Number(req.body.quantity) || 1;
      pricePerKg = Number(req.body.pricePerKg) || 0;
    } else {
      return res.status(400).json({ success: false, error: "Imagem ausente" });
    }

    const material = await Material.create({
      userId: req.user.id,
      type,
      quantity,
      pricePerKg,
      photoBase64,
    });

    res.json({ success: true, material });
  } catch (e) {
    console.error("Upload error:", e);
    res.status(500).json({ success: false, error: "Erro ao salvar" });
  }
});

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

// Start
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend rodando na porta ${PORT}`);
});

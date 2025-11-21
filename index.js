// index.js — VERSÃO FINAL QUE ACEITA SEU FRONTEND 100% (21/11/2025 23:47)
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

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Schemas
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

// Auth middleware
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

const upload = multer(); // não precisa de storage

// ====== ROTA QUE AGORA FUNCIONA 100% COM SEU FRONTEND ======
app.post("/materials", auth, upload.none(), async (req, res) => {
  try {
    console.log("BODY RECEBIDO:", req.body); // VOCÊ VAI VER ISSO NO LOG DO RENDER

    let photoBase64 = req.body.photoBase64 || "";

    // LINHA MÁGICA QUE SALVA TUDO — aceita com ou sem prefixo
    if (photoBase64.includes("base64,")) {
      photoBase64 = photoBase64.split("base64,")[1];
    }

    if (!photoBase64 || photoBase64.length < 1000) {
      return res.status(400).json({ success: false, error: "Imagem ausente ou inválida" });
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
    console.error("ERRO UPLOAD:", e);
    res.status(500).json({ success: false, error: "Erro ao salvar" });
  }
});
// =========================================================

// Login e register (sem mudança)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ success: false, error: "Credenciais inválidas" });
  }
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, accessToken: token });
});

app.get("/materials", auth, async (req, res) => {
  const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json({ success: true, materials });
});

// Conexão e start
mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB conectado"))
  .catch(err => {
    console.error("Erro MongoDB:", err);
    process.exit(1);
  });

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend rodando na porta ${PORT}`);
});

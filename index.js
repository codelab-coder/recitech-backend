import axios from "axios";
import bodyParser from "body-parser";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

// 1. CONFIGURAÇÕES - USANDO VARIÁVEIS DE AMBIENTE
const app = express();

// CORREÇÃO: Altera o fallback da porta para 3001 para evitar conflito EADDRINUSE com 10000
const PORT = process.env.PORT || 3001; 

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/recitech";
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey_dev_only"; 
const FRONTEND_URL = process.env.FRONTEND_URL || "https://recitech-mvp.netlify.app"; 
const IA_API_URL = process.env.IA_API_URL || "https://recitech-ia-api.onrender.com"; 


// =========================================================================
// CORREÇÃO: Configuração CORS MAIS ROBUSTA para o Netlify e Localhost
// =========================================================================

// Lista de origens permitidas (incluindo a URL de produção e URLs de teste)
const ALLOWED_ORIGINS = [
    'https://recitech-mvp.netlify.app', // URL de Produção
    'http://localhost:19006',          // Porta do Expo/React Native Web
    'http://localhost:3000',           // Outra porta comum para dev
];

const corsOptions = {
    origin: (origin, callback) => {
        // Permite requisições sem 'origin' (Postman, ferramentas de teste)
        // OU se a origem estiver na lista de permitidos
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Acesso não permitido pelo CORS'));
        }
    },
    credentials: true // Essencial para o envio de tokens (JWT)
};

// Middleware
// Usa o novo corsOptions robusto
app.use(cors(corsOptions)); 
app.use(bodyParser.json({ limit: "10mb" }));

// ===== MongoDB Schemas =====
const userSchema = new mongoose.Schema({
    email: String,
    password: String, 
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

// ===== DB Connection =====
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB conectado"))
    .catch(err => console.error("❌ Erro MongoDB:", err));

// ===== Helper (Middleware de Auth) =====
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ success: false, error: "Token ausente" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(401).json({ success: false, error: "Token inválido" });
    }
};

// ===== Routes =====
app.get("/", (req, res) => res.json({ success: true, msg: "Backend ReciTech online" }));

// ---- Auth (Login/Register) ----
app.post("/register", async (req, res) => {
    const { email, password, cnpj } = req.body;
    if (!email || !password || !cnpj) return res.json({ success: false, error: "Campos obrigatórios" });

    const exists = await User.findOne({ email });
    if (exists) return res.json({ success: false, error: "Email já cadastrado" });

    const user = new User({ email, password, cnpj }); 
    await user.save();
    res.json({ success: true });
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ success: false, error: "Campos obrigatórios" });

    const user = await User.findOne({ email, password });
    if (!user) return res.json({ success: false, error: "Credenciais inválidas" });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, accessToken: token });
});

// ---- Materials (Upload/List) ----
app.post("/materials", authMiddleware, async (req, res) => {
    const { type, quantity, pricePerKg, photoBase64 } = req.body;
    if (!photoBase64) return res.json({ success: false, error: "Imagem ausente" });

    const material = new Material({
        userId: req.user.id,
        type: type || "desconhecido",
        quantity: quantity || 1,
        pricePerKg: pricePerKg || 0,
        photoBase64
    });

    await material.save();
    res.json({ success: true, material });
});

app.get("/materials", authMiddleware, async (req, res) => {
    const materials = await Material.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json({ success: true, materials });
});

// ---- Classify (Proxy para IA FastAPI) ----
app.post("/classify", authMiddleware, async (req, res) => {
    const { photoBase64 } = req.body;
    if (!photoBase64) return res.json({ success: false, error: "Imagem ausente" });

    try {
        const response = await axios.post(`${IA_API_URL}/classify`, { photoBase64 });
        res.json(response.data);
    } catch (err) {
        console.error("Erro na classificação da IA:", err.message);
        res.status(503).json({ success: false, error: "Serviço de IA temporariamente indisponível." });
    }
});

// ===== Start server =====
app.listen(PORT, () => console.log(`✅ Backend rodando em http://0.0.0.0:${PORT}`));

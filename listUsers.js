require('dotenv').config();
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: String,
  passwordHash: String,
});

const User = mongoose.model('User', userSchema);

async function listUsers() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB conectado.');

    const users = await User.find({});
    console.log('Usuários cadastrados:', users);

    await mongoose.disconnect();
    console.log('Desconectado do MongoDB.');
  } catch (err) {
    console.error('Erro:', err);
  }
}

listUsers();

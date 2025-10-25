require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: String,
  passwordHash: String,
});
const User = mongoose.model('User', userSchema);

async function createUser() {
  await mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  const username = 'testuser';
  const password = 'test1234';

  const existing = await User.findOne({ username });
  if (existing) {
    console.log('Usuário já existe');
    process.exit(0);
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = new User({ username, passwordHash });
  await user.save();

  console.log(`Usuário ${username} criado com sucesso!`);
  mongoose.disconnect();
}

createUser().catch(console.error);

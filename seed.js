// seed.js (exemplo básico)
const fs = require('fs');
const mongoose = require('mongoose');
// importe suas models aqui: const User = require('./models/User'); etc.

const data = JSON.parse(fs.readFileSync('./fake-seed.json', 'utf8'));

async function seed() {
  await mongoose.connect('mongodb://localhost:27017/recitech'); // ajuste a URL
  await User.deleteMany({});
  await Listing.deleteMany({});
  await Transaction.deleteMany({});

  await User.insertMany(data.users);
  await Listing.insertMany(data.listings);
  await Transaction.insertMany(data.transactions);

  console.log('Dados fictícios importados com sucesso!');
  process.exit(0);
}

seed().catch(err => {
  console.error(err);
  process.exit(1);
});

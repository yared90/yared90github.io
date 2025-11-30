// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const util = require('util');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET = process.env.JWT_SECRET || 'replace_this_with_a_real_secret';
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('./brand.db');
const run = util.promisify(db.run.bind(db));
const get = util.promisify(db.get.bind(db));
const all = util.promisify(db.all.bind(db));

// init
(async function init(){
  await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, role TEXT)`);
  await run(`CREATE TABLE IF NOT EXISTS submissions (id INTEGER PRIMARY KEY, data TEXT, createdAt TEXT)`);

  // ensure demo accounts
  const demoUsers = [
    {email:'employer@gmail.com', password:'123456', role:'employer'},
    {email:'jobseeker@gmail.com', password:'123456', role:'jobseeker'},
    {email:'admin@brandagent.com', password:'admin123', role:'admin'}
  ];
  for(const u of demoUsers){
    const row = await get('SELECT id FROM users WHERE email = ?', [u.email]);
    if(!row){
      const hash = await bcrypt.hash(u.password, 10);
      await run('INSERT INTO users (email,password,role) VALUES (?,?,?)', [u.email, hash, u.role]);
      console.log('Inserted demo user', u.email);
    }
  }
})().catch(err=> console.error(err));

// helpers
function signToken(payload){
  return jwt.sign(payload, SECRET, {expiresIn:'24h'});
}

function verifyToken(token){
  try{
    return jwt.verify(token, SECRET);
  }catch(e){
    return null;
  }
}

// routes
app.post('/api/register', async (req,res)=>{
  try{
    const {email,password,role} = req.body;
    if(!email || !password) return res.status(400).json({error:'missing email/password'});
    const hashed = await bcrypt.hash(password, 10);
    await run('INSERT INTO users (email,password,role) VALUES (?,?,?)', [email.toLowerCase(), hashed, role || 'jobseeker']);
    return res.json({ok:true});
  }catch(err){
    if(err && String(err).includes('UNIQUE constraint')) return res.status(400).json({error:'user exists'});
    console.error(err);
    return res.status(500).json({error:err.message});
  }
});

app.post('/api/login', async (req,res)=>{
  try{
    const {email,password} = req.body;
    if(!email || !password) return res.status(400).json({error:'missing'});
    const row = await get('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
    if(!row) return res.status(401).json({error:'no user'});
    const ok = await bcrypt.compare(password, row.password);
    if(!ok) return res.status(401).json({error:'wrong password'});
    // For admin OTP simulation: in production integrate SMS provider
    // Issue JWT
    const token = signToken({id: row.id, email: row.email, role: row.role});
    res.json({token, role: row.role});
  }catch(err){
    console.error(err);
    res.status(500).json({error:err.message});
  }
});

app.post('/api/submit', async (req,res)=>{
  try{
    const data = req.body;
    const str = JSON.stringify(data);
    const createdAt = new Date().toISOString();
    const r = await run('INSERT INTO submissions (data, createdAt) VALUES (?,?)', [str, createdAt]);
    // sqlite3 run doesn't return lastID when promisified simply, so query last row:
    const last = await get('SELECT last_insert_rowid() as id');
    res.json({ok:true, id: last.id});
  }catch(err){
    console.error(err);
    res.status(500).json({error:err.message});
  }
});

// admin-only submissions
app.get('/api/submissions', async (req,res)=>{
  try{
    const auth = req.headers.authorization || '';
    const token = auth.split(' ')[1];
    const payload = verifyToken(token);
    if(!payload) return res.status(401).json({error:'unauthorized'});
    if(payload.role !== 'admin') return res.status(403).json({error:'forbidden'});

    const rows = await all('SELECT id, data, createdAt FROM submissions ORDER BY id DESC');
    // send data as objects for convenience
    const out = rows.map(r => ({id: r.id, data: r.data, createdAt: r.createdAt}));
    res.json(out);
  }catch(err){
    console.error(err);
    res.status(500).json({error:err.message});
  }
});

// optional admin users listing (admin-only)
app.get('/api/users', async (req,res)=>{
  try{
    const auth = req.headers.authorization || '';
    const token = auth.split(' ')[1];
    const payload = verifyToken(token);
    if(!payload) return res.status(401).json({error:'unauthorized'});
    if(payload.role !== 'admin') return res.status(403).json({error:'forbidden'});
    const rows = await all('SELECT id,email,role FROM users ORDER BY id DESC');
    res.json(rows);
  }catch(err){
    console.error(err);
    res.status(500).json({error:err.message});
  }
});

app.listen(PORT, ()=> console.log(`Server listening on http://localhost:${PORT}`));

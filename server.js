'use strict';
const express = require('express');
const session = require('express-session');

const Database = require('./db');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
for (const d of ['data', 'uploads']) fs.mkdirSync(path.join(ROOT, d), {recursive:true});
const db = new Database(path.join(ROOT, 'data', 'marketplace.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 phone TEXT NOT NULL DEFAULT '',
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('customer','seller','admin')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 seller_id INTEGER NOT NULL REFERENCES users(id),
 name TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '',
 category TEXT NOT NULL DEFAULT 'General',
 price_paisa INTEGER NOT NULL CHECK(price_paisa >= 0),
 stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
 image TEXT NOT NULL DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 customer_id INTEGER NOT NULL REFERENCES users(id),
 seller_id INTEGER NOT NULL REFERENCES users(id),
 total_paisa INTEGER NOT NULL,
 payment_method TEXT NOT NULL,
 payment_status TEXT NOT NULL DEFAULT 'pending',
 order_status TEXT NOT NULL DEFAULT 'new',
 customer_name TEXT NOT NULL,
 customer_phone TEXT NOT NULL,
 shipping_address TEXT NOT NULL,
 provider_reference TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 product_id INTEGER NOT NULL REFERENCES products(id),
 product_name TEXT NOT NULL,
 price_paisa INTEGER NOT NULL,
 quantity INTEGER NOT NULL CHECK(quantity > 0)
);
CREATE TABLE IF NOT EXISTS payment_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL REFERENCES orders(id),
 provider TEXT NOT NULL,
 event_type TEXT NOT NULL,
 provider_reference TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.urlencoded({extended:false, limit:'30kb'}));
app.use(express.json({limit:'30kb'}));
app.use(session({
 name:'market.sid',
 secret:process.env.SESSION_SECRET || 'CHANGE_THIS_SECRET_BEFORE_PUBLIC_DEPLOYMENT_' + crypto.randomBytes(20).toString('hex'),
 resave:false,
 saveUninitialized:false,
 
 cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV === 'production',maxAge:1000*60*60*24*7}
}));
// Require login for all website pages and API routes except authentication.
app.use((req,res,next)=>{
 if(req.path.startsWith('/api/')){
  if(['/api/csrf','/api/me','/api/register','/api/login'].includes(req.path)) return next();
  return requireAuth(req,res,next);
 }
 if(req.path === '/login.html') return next();
 if(!currentUser(req)) return res.redirect('/login.html');
 next();
});

app.use('/uploads', express.static(path.join(ROOT,'uploads'), {fallthrough:false, maxAge:'1d'}));
app.use(express.static(path.join(ROOT,'public')));
const authLimiter = rateLimit({windowMs:15*60*1000, limit:30, standardHeaders:true, legacyHeaders:false});
const upload = multer({
 storage:multer.diskStorage({
  destination:(req,file,cb)=>cb(null,path.join(ROOT,'uploads')),
  filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())
 }),
 limits:{fileSize:3*1024*1024, files:1},
 fileFilter:(req,file,cb)=>{
  const allowed={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp'};
  if(!allowed[file.mimetype]) return cb(new Error('Sirf JPG, PNG ya WEBP image upload karein.'));
  cb(null,true);
 }
});
const safeUser = u => ({id:u.id,name:u.name,email:u.email,phone:u.phone,role:u.role});
function currentUser(req){return req.session.user || null;}
function requireAuth(req,res,next){if(!currentUser(req)) return res.status(401).json({error:'Pehle login karein.'});next();}
function requireSeller(req,res,next){if(!currentUser(req)||!['seller','admin'].includes(currentUser(req).role))return res.status(403).json({error:'Seller account zaroori hai.'});next();}
function requireAdmin(req,res,next){if(!currentUser(req)||currentUser(req).role!=='admin')return res.status(403).json({error:'Admin access zaroori hai.'});next();}
function text(v,max=200){return typeof v==='string'?v.trim().slice(0,max):'';}
function rupees(paisa){return (paisa/100).toFixed(2);}
function moneyToPaisa(value){
 const n=Number(value);
 if(!Number.isFinite(n)||n<0||n>100000000) return null;
 return Math.round(n*100);
}
function csrf(req){if(!req.session.csrf)req.session.csrf=crypto.randomBytes(24).toString('hex');return req.session.csrf;}
function checkCsrf(req,res,next){
 const token=req.get('x-csrf-token') || req.body?._csrf;
 if(!token || token!==req.session.csrf) return res.status(403).json({error:'Security token expired. Page refresh karein.'});
 next();
}
app.get('/api/csrf',(req,res)=>res.json({token:csrf(req)}));
app.get('/api/me',(req,res)=>res.json({user:currentUser(req)}));

app.post('/api/register',authLimiter,checkCsrf,async(req,res)=>{
 const name=text(req.body.name,80), email=text(req.body.email,160).toLowerCase();
 const phone=text(req.body.phone,30), password=String(req.body.password||''), role=req.body.role;
 if(name.length<2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<10 || password.length>72 || !['customer','seller'].includes(role))
  return res.status(400).json({error:'Naam, valid email, customer/seller role aur 10-72 character password dein.'});
 try{
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare('INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)').run(name,email,phone,hash,role);
  const user=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  req.session.regenerate(err=>{
   if(err)return res.status(500).json({error:'Session create nahi hui.'});
   req.session.user=safeUser(user);req.session.csrf=crypto.randomBytes(24).toString('hex');
   res.status(201).json({user:req.session.user,csrf:req.session.csrf});
  });
 }catch(e){if(String(e.code)==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'Is email ka account pehle se hai.'});res.status(500).json({error:'Registration failed.'});}
});
app.post('/api/login',authLimiter,checkCsrf,async(req,res)=>{
 const email=text(req.body.email,160).toLowerCase(), password=String(req.body.password||'');
 const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!user || !(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Email ya password ghalat hai.'});
 req.session.regenerate(err=>{
  if(err)return res.status(500).json({error:'Session create nahi hui.'});
  req.session.user=safeUser(user);req.session.csrf=crypto.randomBytes(24).toString('hex');
  res.json({user:req.session.user,csrf:req.session.csrf});
 });
});
app.post('/api/logout',requireAuth,checkCsrf,(req,res)=>req.session.destroy(()=>{res.clearCookie('market.sid');res.json({ok:true});}));

app.get('/api/products',(req,res)=>{
 const q=text(req.query.q,80), category=text(req.query.category,60);
 const page=Math.max(1,Math.min(10000,Number(req.query.page)||1));
 const limit=Math.max(1,Math.min(50,Number(req.query.limit)||50));
 let where='p.active=1', args=[];
 if(q){where+=' AND (p.name LIKE ? OR p.description LIKE ?)';args.push('%'+q+'%','%'+q+'%');}
 if(category){where+=' AND p.category=?';args.push(category);}
 const total=db.prepare(`SELECT COUNT(*) AS n FROM products p WHERE ${where}`).get(...args).n;
 const rows=db.prepare(`SELECT p.id,p.name,p.description,p.category,p.price_paisa,p.stock,p.image,p.seller_id,u.name AS seller_name FROM products p JOIN users u ON u.id=p.seller_id WHERE ${where} ORDER BY p.id DESC LIMIT ? OFFSET ?`).all(...args,limit,(page-1)*limit);
 res.json({products:rows.map(p=>({...p,price:rupees(p.price_paisa)})),total,page,limit});
});
app.get('/api/categories',(req,res)=>res.json(db.prepare('SELECT DISTINCT category FROM products WHERE active=1 ORDER BY category').all().map(x=>x.category)));

app.post('/api/products',requireAuth,requireSeller,checkCsrf,upload.single('image'),(req,res)=>{
 const name=text(req.body.name,100), description=text(req.body.description,1000), category=text(req.body.category,60)||'General';
 const price=moneyToPaisa(req.body.price), stock=Number(req.body.stock);
 if(name.length<2||price===null||!Number.isInteger(stock)||stock<0||stock>1000000){
  if(req.file)fs.unlinkSync(req.file.path);
  return res.status(400).json({error:'Product name, valid price aur stock check karein.'});
 }
 const image=req.file?'/uploads/'+req.file.filename:'';
 const result=db.prepare('INSERT INTO products(seller_id,name,description,category,price_paisa,stock,image) VALUES(?,?,?,?,?,?,?)')
  .run(currentUser(req).id,name,description,category,price,stock,image);
 res.status(201).json({ok:true,id:result.lastInsertRowid});
});
app.put('/api/products/:id',requireAuth,requireSeller,checkCsrf,upload.single('image'),(req,res)=>{
 const id=Number(req.params.id), product=db.prepare('SELECT * FROM products WHERE id=?').get(id);
 if(!product)return res.status(404).json({error:'Product nahi mila.'});
 if(currentUser(req).role!=='admin'&&product.seller_id!==currentUser(req).id)return res.status(403).json({error:'Sirf apna product edit kar sakte hain.'});
 const name=text(req.body.name,100), description=text(req.body.description,1000), category=text(req.body.category,60)||'General';
 const price=moneyToPaisa(req.body.price),stock=Number(req.body.stock);
 if(name.length<2||price===null||!Number.isInteger(stock)||stock<0||stock>1000000){if(req.file)fs.unlinkSync(req.file.path);return res.status(400).json({error:'Product fields check karein.'});}
 const image=req.file?'/uploads/'+req.file.filename:product.image;
 db.prepare('UPDATE products SET name=?,description=?,category=?,price_paisa=?,stock=?,image=? WHERE id=?').run(name,description,category,price,stock,image,id);
 res.json({ok:true});
});
app.delete('/api/products/:id',requireAuth,requireSeller,checkCsrf,(req,res)=>{
 const p=db.prepare('SELECT * FROM products WHERE id=?').get(Number(req.params.id));
 if(!p)return res.status(404).json({error:'Product nahi mila.'});
 if(currentUser(req).role!=='admin'&&p.seller_id!==currentUser(req).id)return res.status(403).json({error:'Sirf apna product delete kar sakte hain.'});
 db.prepare('UPDATE products SET active=0 WHERE id=?').run(p.id);res.json({ok:true});
});

const paymentMethods=['COD','CARD','JAZZCASH','EASYPAISA'];
app.get('/api/payments/methods',(req,res)=>res.json({methods:[
 {id:'COD',label:'Cash on Delivery',available:true},
 {id:'CARD',label:'Debit / Credit Card',available:false,detail:'Live merchant gateway credentials required'},
 {id:'JAZZCASH',label:'JazzCash',available:false,detail:'Merchant account and API credentials required'},
 {id:'EASYPAISA',label:'Easypaisa',available:false,detail:'Merchant account and API credentials required'}
]}));
app.post('/api/orders',requireAuth,checkCsrf,(req,res)=>{
 const items=Array.isArray(req.body.items)?req.body.items:[];
 const method=text(req.body.payment_method,20);
 const customer_name=text(req.body.customer_name,80), customer_phone=text(req.body.customer_phone,30), address=text(req.body.address,500);
 if(!items.length||items.length>50||!customer_name||customer_phone.length<7||address.length<8||!paymentMethods.includes(method))
  return res.status(400).json({error:'Cart, naam, phone, address aur payment method check karein.'});
 if(method!=='COD')return res.status(400).json({error:'Yeh online method abhi live configured nahi hai. COD choose karein jab tak merchant gateway setup na ho.'});
 const normalized=[];
 for(const item of items){
  const id=Number(item.id),qty=Number(item.quantity);
  if(!Number.isInteger(id)||!Number.isInteger(qty)||qty<1||qty>20)return res.status(400).json({error:'Invalid product quantity.'});
  const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(id);
  if(!p||p.stock<qty)return res.status(400).json({error:'Product unavailable ya stock kam hai: '+(p?p.name:'product')});
  normalized.push({p,qty});
 }
 const create=db.transaction(()=>{
  const grouped=new Map();
  for(const item of normalized){const key=item.p.seller_id;if(!grouped.has(key))grouped.set(key,[]);grouped.get(key).push(item);}
  const orderIds=[];
  for(const [sellerId,rows] of grouped){
   const total=rows.reduce((sum,x)=>sum+x.p.price_paisa*x.qty,0);
   const info=db.prepare(`INSERT INTO orders(customer_id,seller_id,total_paisa,payment_method,payment_status,customer_name,customer_phone,shipping_address) VALUES(?,?,?,?,?,?,?,?)`)
    .run(currentUser(req).id,sellerId,total,method,'pending',customer_name,customer_phone,address);
   const oid=Number(info.lastInsertRowid);orderIds.push({id:oid,total:rupees(total)});
   for(const x of rows){
    db.prepare('INSERT INTO order_items(order_id,product_id,product_name,price_paisa,quantity) VALUES(?,?,?,?,?)').run(oid,x.p.id,x.p.name,x.p.price_paisa,x.qty);
    db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(x.qty,x.p.id);
   }
   db.prepare('INSERT INTO payment_events(order_id,provider,event_type) VALUES(?,?,?)').run(oid,'COD','created_pending_collection');
  }
  return orderIds;
 });
 try{res.status(201).json({ok:true,orders:create(),message:'Order place ho gaya. Payment delivery par collect hogi.'});}
 catch(e){res.status(400).json({error:'Order save nahi ho saka. Stock dobara check karein.'});}
});
app.get('/api/my-orders',requireAuth,(req,res)=>{
 const orders=db.prepare('SELECT * FROM orders WHERE customer_id=? ORDER BY id DESC LIMIT 100').all(currentUser(req).id);
 res.json(orders.map(o=>({...o,total:rupees(o.total_paisa),items:db.prepare('SELECT product_name,price_paisa,quantity FROM order_items WHERE order_id=?').all(o.id).map(i=>({...i,price:rupees(i.price_paisa)}))})));
});
app.get('/api/seller/summary',requireAuth,requireSeller,(req,res)=>{
 const id=currentUser(req).id, admin=currentUser(req).role==='admin';
 const products=admin?db.prepare('SELECT COUNT(*) n FROM products WHERE active=1').get().n:db.prepare('SELECT COUNT(*) n FROM products WHERE seller_id=? AND active=1').get(id).n;
 const orders=admin?db.prepare("SELECT COUNT(*) n FROM orders").get().n:db.prepare("SELECT COUNT(*) n FROM orders WHERE seller_id=?").get(id).n;
 const sales=admin?db.prepare("SELECT COALESCE(SUM(total_paisa),0) n FROM orders").get().n:db.prepare("SELECT COALESCE(SUM(total_paisa),0) n FROM orders WHERE seller_id=? AND order_status!='cancelled'").get(id).n;
 res.json({products,orders,sales:rupees(sales)});
});
app.get('/api/seller/products',requireAuth,requireSeller,(req,res)=>{
 const u=currentUser(req), admin=u.role==='admin';
 const rows=admin?db.prepare('SELECT * FROM products ORDER BY id DESC').all():db.prepare('SELECT * FROM products WHERE seller_id=? ORDER BY id DESC').all(u.id);
 res.json(rows.map(p=>({...p,price:rupees(p.price_paisa)})));
});
app.get('/api/seller/orders',requireAuth,requireSeller,(req,res)=>{
 const u=currentUser(req),admin=u.role==='admin';
 const rows=admin?db.prepare('SELECT * FROM orders ORDER BY id DESC LIMIT 200').all():db.prepare('SELECT * FROM orders WHERE seller_id=? ORDER BY id DESC LIMIT 200').all(u.id);
 res.json(rows.map(o=>({...o,total:rupees(o.total_paisa),items:db.prepare('SELECT product_name,quantity,price_paisa FROM order_items WHERE order_id=?').all(o.id)})));
});
app.post('/api/seller/orders/:id/status',requireAuth,requireSeller,checkCsrf,(req,res)=>{
 const id=Number(req.params.id),status=text(req.body.status,30),u=currentUser(req);
 if(!['processing','shipped','delivered','cancelled'].includes(status))return res.status(400).json({error:'Invalid status.'});
 const o=db.prepare('SELECT * FROM orders WHERE id=?').get(id);
 if(!o)return res.status(404).json({error:'Order not found.'});
 if(u.role!=='admin'&&o.seller_id!==u.id)return res.status(403).json({error:'Access denied.'});
 if(status==='cancelled'&&o.order_status!=='cancelled'){
  const items=db.prepare('SELECT product_id,quantity FROM order_items WHERE order_id=?').all(id);
  const tx=db.transaction(()=>{for(const i of items)db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(i.quantity,i.product_id);db.prepare("UPDATE orders SET order_status='cancelled' WHERE id=?").run(id);});
  tx();
 }else db.prepare('UPDATE orders SET order_status=? WHERE id=?').run(status,id);
 res.json({ok:true});
});
app.get('/api/admin/users',requireAuth,requireAdmin,(req,res)=>res.json(db.prepare('SELECT id,name,email,role,created_at FROM users ORDER BY id DESC LIMIT 500').all()));

app.use((err,req,res,next)=>{
 if(err instanceof multer.MulterError)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'Image 3MB se chhoti honi chahiye.':'Image upload error.'});
 if(err) return res.status(400).json({error:err.message||'Request error.'});
 next();
});
app.listen(PORT,HOST,()=>console.log(`Marketplace running: http://${HOST}:${PORT}\nPress Ctrl+C to stop.`));

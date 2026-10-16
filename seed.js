'use strict';
const Database=require('./db');
const bcrypt=require('bcryptjs');
const path=require('path');
const fs=require('fs');
fs.mkdirSync(path.join(__dirname,'data'),{recursive:true});
const db=new Database(path.join(__dirname,'data','marketplace.sqlite'));
(async()=>{
 const email='demo.seller@example.com';
 let seller=db.prepare('SELECT id FROM users WHERE email=?').get(email);
 if(!seller){
  const hash=await bcrypt.hash('ChangeMe123!',12);
  const info=db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,?)").run('Demo Seller',email,'03001234567',hash,'seller');
  seller={id:Number(info.lastInsertRowid)};
 }
 const samples=[
 ['Classic Cotton T-Shirt','Soft everyday cotton tee.','Fashion',1200,25,'👕'],
 ['Running Sneakers','Comfortable daily running shoes.','Fashion',4200,12,'👟'],
 ['Everyday Backpack','Lightweight backpack for daily use.','Bags',2300,18,'🎒'],
 ['Smart Watch','Smart watch with daily activity features.','Electronics',5500,10,'⌚'],
 ['Wireless Earbuds','Compact wireless audio earbuds.','Electronics',2800,20,'🎧'],
 ['Phone Case','Protective case for popular phones.','Accessories',450,40,'📱'],
 ['USB-C Cable','Durable charging and data cable.','Electronics',350,50,'🔌'],
 ['Power Bank 10000mAh','Portable battery for travel.','Electronics',3200,14,'🔋'],
 ['Bluetooth Speaker','Portable speaker for music.','Electronics',2600,15,'🔊'],
 ['Desk Lamp','LED desk lamp for study and work.','Home',1500,17,'💡'],
 ['Ceramic Coffee Mug','Reusable ceramic coffee mug.','Home',500,30,'☕'],
 ['Water Bottle','Reusable everyday water bottle.','Home',650,32,'🧴'],
 ['Kitchen Storage Set','Organize pantry essentials.','Home',1100,16,'🥣'],
 ['Nonstick Frying Pan','Everyday nonstick cooking pan.','Home',1900,9,'🍳'],
 ['Cotton Bedsheet','Soft bedsheet set for bedroom.','Home',2500,8,'🛏️'],
 ['Bath Towel','Soft absorbent bath towel.','Home',700,28,'🧖'],
 ['Sunglasses','Classic everyday sunglasses.','Fashion',950,21,'🕶️'],
 ['Leather Wallet','Slim wallet for cards and cash.','Fashion',800,19,'👛'],
 ['Baseball Cap','Adjustable casual cap.','Fashion',550,22,'🧢'],
 ['Casual Hoodie','Comfortable hoodie for cool weather.','Fashion',2100,11,'🧥'],
 ['Yoga Mat','Non-slip exercise and yoga mat.','Sports',1800,10,'🧘'],
 ['Skipping Rope','Fitness skipping rope.','Sports',350,24,'🏃'],
 ['Football','Durable football for recreation.','Sports',1300,13,'⚽'],
 ['Cricket Bat','Practice cricket bat.','Sports',2400,7,'🏏'],
 ['Resistance Bands','Home workout resistance band set.','Sports',750,18,'💪'],
 ['Notebook Set','Notebooks for school and office.','Stationery',400,40,'📓'],
 ['Ballpoint Pens','Pack of smooth-writing pens.','Stationery',180,60,'🖊️'],
 ['Backpack Organizer','Small organizer for stationery.','Stationery',650,16,'🗂️'],
 ['Desk Organizer','Keep your desk tidy.','Stationery',900,12,'🗄️'],
 ['Reading Light','Clip-on light for reading.','Home',700,15,'📖'],
 ['Face Wash','Gentle daily face cleanser.','Beauty',650,20,'🧼'],
 ['Moisturizing Lotion','Everyday skin moisturizer.','Beauty',850,18,'🧴'],
 ['Hair Brush','Everyday hair brush.','Beauty',300,30,'💇'],
 ['Makeup Pouch','Compact pouch for cosmetics.','Beauty',550,14,'👝'],
 ['Perfume Gift Set','Gift-ready fragrance set.','Beauty',2200,9,'🌸'],
 ['Baby Blanket','Soft baby blanket.','Baby',1300,10,'🧸'],
 ['Baby Feeding Bottle','Reusable baby feeding bottle.','Baby',500,20,'🍼'],
 ['Kids Building Blocks','Creative building block set.','Toys',1700,12,'🧱'],
 ['Stuffed Teddy Bear','Soft plush teddy bear.','Toys',900,16,'🧸'],
 ['Puzzle Game','Family-friendly puzzle.','Toys',750,18,'🧩'],
 ['Car Phone Holder','Phone holder for car dashboard.','Automotive',650,17,'🚘'],
 ['Car Charger','Dual-port car charger.','Automotive',800,15,'🚗'],
 ['Microfiber Cleaning Cloth','Reusable cleaning cloth set.','Home',250,35,'🧽'],
 ['Reusable Shopping Bag','Foldable shopping tote.','Accessories',220,40,'🛍️'],
 ['Travel Neck Pillow','Comfortable travel neck pillow.','Travel',900,11,'✈️'],
 ['Luggage Tag Set','Colorful luggage tags.','Travel',300,20,'🏷️'],
 ['Lunch Box','Reusable lunch box for work or school.','Home',700,23,'🍱'],
 ['Thermal Flask','Insulated flask for hot or cold drinks.','Home',1400,12,'🫖'],
 ['Table Clock','Compact clock for desk or bedside.','Home',950,10,'⏰'],
 ['Mini Tripod','Compact tripod for phone photography.','Electronics',1100,9,'📷']
 ];
 const insert=db.prepare('INSERT INTO products(seller_id,name,description,category,price_paisa,stock,image) VALUES(?,?,?,?,?,?,?)');
 const exists=db.prepare('SELECT COUNT(*) n FROM products').get().n;
 if(exists===0){
  const tx=db.transaction(()=>samples.forEach((p,i)=>insert.run(seller.id,p[0],p[1],p[2],p[3]*100,p[4],`/emoji/${encodeURIComponent(p[5])}`)));
  tx();
 }
 console.log(`Seed complete. ${db.prepare('SELECT COUNT(*) n FROM products WHERE active=1').get().n} products in database.`);
 console.log('Demo seller login: demo.seller@example.com / ChangeMe123!');
 console.log('Change this demo password immediately; do not expose demo credentials on a public deployment.');
 db.close();
})().catch(e=>{console.error(e);process.exit(1)});

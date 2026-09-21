import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import path from "node:path";
import {fileURLToPath} from "node:url";
import dns from "node:dns/promises";
import net from "node:net";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const db=new Database(process.env.DB_PATH||"library.db");
db.pragma("journal_mode=WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS media(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,category TEXT NOT NULL,season TEXT,quality TEXT,url TEXT NOT NULL,description TEXT,poster TEXT,status TEXT NOT NULL DEFAULT 'unknown',last_checked TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
`);
const app=express();
app.use(express.json({limit:"64kb"})); app.use(express.urlencoded({extended:false}));
app.use(session({secret:process.env.SESSION_SECRET||"change-me",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*24*60*60*1000}}));
app.use(express.static(path.join(__dirname,"public")));

const auth=(req,res,next)=>req.session.user?next():res.status(401).json({error:"Login required"});
const admin=(req,res,next)=>req.session.user?.role==="admin"?next():res.status(403).json({error:"Admin only"});
const validUrl=u=>{try{const x=new URL(u);return ["http:","https:"].includes(x.protocol)?x:null}catch{return null}};
async function safeReachable(u){
  const x=validUrl(u); if(!x) throw new Error("Only http/https URLs are allowed");
  const host=x.hostname.toLowerCase();
  if(host==="localhost"||host.endsWith(".localhost")||host.endsWith(".local")||net.isIP(host)) {
    if(host==="localhost"||host.endsWith(".local")||net.isIP(host)) throw new Error("Private/local targets are blocked");
  }
  const addrs=await dns.lookup(host,{all:true});
  for(const a of addrs){const ip=a.address;if(ip.startsWith("10.")||ip.startsWith("192.168.")||ip.startsWith("127.")||ip.startsWith("169.254.")||ip.startsWith("172.16.")||ip.startsWith("172.17.")||ip.startsWith("172.18.")||ip.startsWith("172.19.")||ip.startsWith("172.2")||ip.startsWith("172.30.")||ip.startsWith("172.31.")||ip==="::1"||ip.startsWith("fc")||ip.startsWith("fe80:")) throw new Error("Private/local target blocked");}
  }
  const r=await fetch(x,{method:"HEAD",redirect:"manual",signal:AbortSignal.timeout(8000)});
  return {ok:r.ok,status:r.status};
}

app.post("/api/signup",(req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
  if(!/^\S+@\S+\.\S+$/.test(email)||password.length<8)return res.status(400).json({error:"Use a valid email and an 8+ character password"});
  const exists=db.prepare("SELECT id FROM users WHERE email=?").get(email); if(exists)return res.status(409).json({error:"Account already exists"});
  const role=db.prepare("SELECT COUNT(*) c FROM users").get().c===0?"admin":"user";
  const info=db.prepare("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)").run(email,bcrypt.hashSync(password,12),role);
  req.session.user={id:info.lastInsertRowid,email,role}; res.json({user:req.session.user});
});
app.post("/api/login",(req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:"Invalid email or password"});
  req.session.user={id:u.id,email:u.email,role:u.role}; res.json({user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.get("/api/media",auth,(req,res)=>{
  const q=String(req.query.q||"").trim(), cat=String(req.query.category||"").trim();
  let sql="SELECT id,title,category,season,quality,url,description,poster,status,last_checked FROM media WHERE 1=1", args=[];
  if(q){sql+=" AND (title LIKE ? OR description LIKE ?)";args.push("%"+q+"%","%"+q+"%")} if(cat){sql+=" AND category=?";args.push(cat)}
  res.json({media:db.prepare(sql+" ORDER BY title COLLATE NOCASE").all(...args)});
});
app.post("/api/media",auth,admin,(req,res)=>{
  const b=req.body, title=String(b.title||"").trim(), category=String(b.category||"Other"), url=String(b.url||"").trim();
  if(!title||!validUrl(url))return res.status(400).json({error:"Title and a valid http/https URL are required"});
  const r=db.prepare("INSERT INTO media(title,category,season,quality,url,description,poster) VALUES(?,?,?,?,?,?,?)").run(title,category,String(b.season||""),String(b.quality||""),url,String(b.description||""),String(b.poster||""));
  res.json({id:r.lastInsertRowid});
});
app.delete("/api/media/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM media WHERE id=?").run(req.params.id);res.json({ok:true})});
app.post("/api/check/:id",auth,admin,async(req,res)=>{
  const item=db.prepare("SELECT * FROM media WHERE id=?").get(req.params.id); if(!item)return res.status(404).json({error:"Not found"});
  try{const r=await safeReachable(item.url);db.prepare("UPDATE media SET status=?,last_checked=CURRENT_TIMESTAMP WHERE id=?").run(r.ok?"working":"http-"+r.status,item.id);res.json({status:r.ok?"working":"http-"+r.status})}
  catch(e){db.prepare("UPDATE media SET status='error',last_checked=CURRENT_TIMESTAMP WHERE id=?").run(item.id);res.json({status:"error",message:e.message})}
});
app.listen(process.env.PORT||3000,()=>console.log("Library Archive running"));

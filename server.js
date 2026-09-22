import express from "express";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import path from "node:path";
import {fileURLToPath} from "node:url";
import dns from "node:dns/promises";
import net from "node:net";
import crypto from "node:crypto";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const dbPath=process.env.DB_PATH||path.join(__dirname,"library.db");
const db=new Database(dbPath);
db.pragma("journal_mode=WAL");
db.pragma("foreign_keys=ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS media(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,category TEXT NOT NULL,season TEXT,quality TEXT,url TEXT NOT NULL,description TEXT,poster TEXT,status TEXT NOT NULL DEFAULT 'unknown',last_checked TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
`);

const app=express();
app.disable("x-powered-by");
app.set("trust proxy",process.env.TRUST_PROXY==="1"?1:false);
app.use((req,res,next)=>{
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","DENY");
  res.setHeader("Referrer-Policy","no-referrer");
  res.setHeader("Permissions-Policy","camera=(),microphone=(),geolocation=()");
  res.setHeader("Content-Security-Policy","default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' https: data:; style-src 'self'; script-src 'self'; object-src 'none'");
  if(req.path.startsWith("/api/")) res.setHeader("Cache-Control","no-store");
  next();
});
app.use(express.json({limit:"32kb"}));
app.use(express.urlencoded({extended:false,limit:"16kb"}));

const SQLiteStore=SQLiteStoreFactory(session);
app.use(session({
  store:new SQLiteStore({db:"sessions.sqlite",dir:path.dirname(dbPath)}),
  secret:process.env.SESSION_SECRET||"INSECURE_DEV_ONLY_CHANGE_ME",
  resave:false,saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*24*60*60*1000}
}));

const auth=(req,res,next)=>req.session.user?next():res.status(401).json({error:"Login required"});
const admin=(req,res,next)=>req.session.user?.role==="admin"?next():res.status(403).json({error:"Admin only"});
const categories=["Anime","Games","Series","Movies","Music","Other"];
const validUrl=u=>{try{const x=new URL(u);return ["http:","https:"].includes(x.protocol)?x:null}catch{return null}};
const attempts=new Map();
function rateLimit(key,max,windowMs){
  const now=Date.now(), a=attempts.get(key)||[];
  const fresh=a.filter(t=>now-t<windowMs); fresh.push(now); attempts.set(key,fresh);
  return fresh.length<=max;
}
function clientKey(req){return String(req.ip||"unknown").slice(0,80)}
function requireCsrf(req,res,next){
  if(!["POST","PUT","PATCH","DELETE"].includes(req.method)) return next();
  const token=req.get("X-CSRF-Token");
  if(!req.session.csrf||!token||!crypto.timingSafeEqual(Buffer.from(token),Buffer.from(req.session.csrf))) return res.status(403).json({error:"CSRF check failed"});
  next();
}
app.use("/api",requireCsrf);

async function resolvePublic(host){
  if(host==="localhost"||host.endsWith(".localhost")||host.endsWith(".local")) throw new Error("Local targets are blocked");
  const records=await dns.lookup(host,{all:true,verbatim:true});
  if(!records.length) throw new Error("Host did not resolve");
  for(const r of records){
    const ip=r.address;
    if(net.isIP(ip)===4){
      const [a,b]=ip.split(".").map(Number);
      if(a===10||a===127||a===0||a===169&&b===254||a===192&&b===168||a===172&&b>=16&&b<=31) throw new Error("Private/local target blocked");
    }else if(net.isIP(ip)===6){
      if(ip==="::1"||ip.toLowerCase().startsWith("fc")||ip.toLowerCase().startsWith("fd")||ip.toLowerCase().startsWith("fe80:")) throw new Error("Private/local target blocked");
    }
  }
  return records;
}
async function safeReachable(u){
  const x=validUrl(u); if(!x) throw new Error("Only http/https URLs are allowed");
  await resolvePublic(x.hostname);
  const r=await fetch(x,{method:"HEAD",redirect:"manual",signal:AbortSignal.timeout(7000)});
  return {ok:r.ok,status:r.status};
}

app.get("/api/csrf",(req,res)=>{if(!req.session.csrf)req.session.csrf=crypto.randomBytes(32).toString("hex");res.json({token:req.session.csrf})});
app.post("/api/signup",(req,res,next)=>{
  if(!rateLimit("signup:"+clientKey(req),5,15*60*1000)) return res.status(429).json({error:"Too many signup attempts. Try again later."});
  const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||""), invite=String(req.body.invite||"");
  if(!process.env.INVITE_CODE||invite!==process.env.INVITE_CODE) return res.status(403).json({error:"Invite code required"});
  if(!/^\S+@\S+\.\S+$/.test(email)||password.length<12) return res.status(400).json({error:"Use a valid email and a 12+ character password"});
  if(db.prepare("SELECT id FROM users WHERE email=?").get(email)) return res.status(409).json({error:"Account already exists"});
  const role=process.env.ADMIN_EMAIL&&email===process.env.ADMIN_EMAIL.trim().toLowerCase()?"admin":"user";
  const info=db.prepare("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)").run(email,bcrypt.hashSync(password,12),role);
  req.session.regenerate(err=>{if(err)return next(err);req.session.user={id:info.lastInsertRowid,email,role};req.session.csrf=crypto.randomBytes(32).toString("hex");res.json({user:req.session.user,csrf:req.session.csrf})});
});
app.post("/api/login",(req,res,next)=>{
  if(!rateLimit("login:"+clientKey(req),10,10*60*1000)) return res.status(429).json({error:"Too many login attempts. Try again later."});
  const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!u||!bcrypt.compareSync(password,u.password_hash)) return res.status(401).json({error:"Invalid email or password"});
  req.session.regenerate(err=>{if(err)return next(err);req.session.user={id:u.id,email:u.email,role:u.role};req.session.csrf=crypto.randomBytes(32).toString("hex");res.json({user:req.session.user,csrf:req.session.csrf})});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.get("/api/categories",auth,(req,res)=>res.json({categories}));
app.get("/api/media",auth,(req,res)=>{
  const q=String(req.query.q||"").trim(),cat=String(req.query.category||"").trim();
  let sql="SELECT id,title,category,season,quality,url,description,poster,status,last_checked,created_at FROM media WHERE 1=1",args=[];
  if(q){sql+=" AND (title LIKE ? OR description LIKE ?)";args.push("%"+q+"%","%"+q+"%")}
  if(cat&&categories.includes(cat)){sql+=" AND category=?";args.push(cat)}
  res.json({media:db.prepare(sql+" ORDER BY datetime(created_at) DESC,title COLLATE NOCASE").all(...args)});
});
app.post("/api/media",auth,admin,(req,res)=>{
  const b=req.body,title=String(b.title||"").trim(),category=String(b.category||"Other"),url=String(b.url||"").trim();
  if(!title||title.length>160||!categories.includes(category)||!validUrl(url)||url.length>2048)return res.status(400).json({error:"Invalid resource details"});
  const r=db.prepare("INSERT INTO media(title,category,season,quality,url,description,poster) VALUES(?,?,?,?,?,?,?)").run(title,category,String(b.season||"").slice(0,80),String(b.quality||"").slice(0,80),url,String(b.description||"").slice(0,1000),String(b.poster||"").slice(0,2048));
  res.json({id:r.lastInsertRowid});
});
app.delete("/api/media/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM media WHERE id=?").run(Number(req.params.id));res.json({ok:true})});
app.post("/api/check/:id",auth,admin,async(req,res)=>{
  const item=db.prepare("SELECT * FROM media WHERE id=?").get(Number(req.params.id));if(!item)return res.status(404).json({error:"Not found"});
  try{const r=await safeReachable(item.url);db.prepare("UPDATE media SET status=?,last_checked=CURRENT_TIMESTAMP WHERE id=?").run(r.ok?"working":"http-"+r.status,item.id);res.json({status:r.ok?"working":"http-"+r.status})}
  catch(e){db.prepare("UPDATE media SET status='error',last_checked=CURRENT_TIMESTAMP WHERE id=?").run(item.id);res.json({status:"error",message:"Link check failed"})}
});
app.use(express.static(path.join(__dirname,"public"),{etag:true,maxAge:"1h"}));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log("Library Archive running"));

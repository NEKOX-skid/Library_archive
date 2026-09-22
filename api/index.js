import bcrypt from "bcryptjs";
import { neon } from "@neondatabase/serverless";
import crypto from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";

const sql=neon(process.env.DATABASE_URL);
const categories=["Anime","Games","Series","Movies","Music","Other"];


function cookie(name,value,maxAge=604800){return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`}
function parseCookies(req){const out={};for(const p of (req.headers.cookie||"").split(";")){const i=p.indexOf("=");if(i>0)out[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())}return out}
function send(res,status,data,headers={}){res.statusCode=status;for(const [k,v] of Object.entries(headers))res.setHeader(k,v);res.setHeader("Content-Type","application/json");res.end(JSON.stringify(data))}
function security(res){res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("X-Frame-Options","DENY");res.setHeader("Referrer-Policy","no-referrer");res.setHeader("Permissions-Policy","camera=(),microphone=(),geolocation=()");res.setHeader("Content-Security-Policy","default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' https: data:; style-src 'self'; script-src 'self'; object-src 'none'")}
function token(){return crypto.randomBytes(32).toString("hex")}
function sessionUser(req){const c=parseCookies(req),s=sessions.get(c.la_session);return s?.expires>Date.now()?s.user:null}
function csrfFor(req){return readSession(req)?.csrf}
function requireCsrf(req,res){const expected=csrfFor(req),got=req.headers["x-csrf-token"];return expected&&got&&crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(got))}
async function body(req){let s="";for await(const chunk of req)s+=chunk;if(s.length>32768)throw Error("Payload too large");return s?JSON.parse(s):{}}
async function init(){await sql`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`;await sql`CREATE TABLE IF NOT EXISTS media(id SERIAL PRIMARY KEY,title TEXT NOT NULL,category TEXT NOT NULL,season TEXT,quality TEXT,url TEXT NOT NULL,description TEXT,poster TEXT,status TEXT NOT NULL DEFAULT 'unknown',last_checked TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`}
let initialized;
function initOnce(){return initialized??(initialized=init())}
const attempts=new Map();
function allowed(key,max,windowMs){const now=Date.now(),a=(attempts.get(key)||[]).filter(x=>now-x<windowMs);a.push(now);attempts.set(key,a);return a.length<=max}
function ip(req){return String(req.headers["x-forwarded-for"]||req.socket?.remoteAddress||"unknown").split(",")[0].slice(0,80)}
function validUrl(u){try{const x=new URL(u);return ["http:","https:"].includes(x.protocol)?x:null}catch{return null}}
async function publicHost(host){if(host==="localhost"||host.endsWith(".localhost")||host.endsWith(".local"))throw Error("Local target blocked");const rs=await dns.lookup(host,{all:true});for(const r of rs){const x=r.address;if(net.isIP(x)===4){const [a,b]=x.split(".").map(Number);if(a===10||a===127||a===0||(a===169&&b===254)||(a===192&&b===168)||(a===172&&b>=16&&b<=31))throw Error("Private target blocked")}else if(x==="::1"||x.toLowerCase().startsWith("fc")||x.toLowerCase().startsWith("fd")||x.toLowerCase().startsWith("fe80:"))throw Error("Private target blocked")}}
async function check(u){const x=validUrl(u);if(!x)throw Error("Only http/https URLs are allowed");await publicHost(x.hostname);const r=await fetch(x,{method:"HEAD",redirect:"manual",signal:AbortSignal.timeout(7000)});return {ok:r.ok,status:r.status}}

export default async function handler(req,res){
  security(res);res.setHeader("Cache-Control","no-store");
  try{
    await initOnce();
    const url=new URL(req.url,"https://library.local"), path=url.pathname, method=req.method;
    const sess=readSession(req);const user=sess? (await sql`SELECT id,email,role FROM users WHERE id=${sess.id}`)[0] : null;
    if(path==="/api/me"&&method==="GET")return send(res,200,{user:user||null});
    if(path==="/api/csrf"&&method==="GET"){if(!user)return send(res,401,{error:"Login required"});const s=readSession(req);return send(res,200,{token:s.csrf})}
    if(path==="/api/signup"&&method==="POST"){
      if(!allowed("signup:"+ip(req),5,900000))return send(res,429,{error:"Too many signup attempts"});
      const b=await body(req),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||""),invite=String(b.invite||"");
      if(!process.env.INVITE_CODE||invite!==process.env.INVITE_CODE)return send(res,403,{error:"Invite code required"});
      if(!/^\S+@\S+\.\S+$/.test(email)||password.length<12)return send(res,400,{error:"Use a valid email and a 12+ character password"});
      if((await sql`SELECT id FROM users WHERE email=${email}`).length)return send(res,409,{error:"Account already exists"});
      const role=process.env.ADMIN_EMAIL?.trim().toLowerCase()===email?"admin":"user";
      const rows=await sql`INSERT INTO users(email,password_hash,role) VALUES(${email},${bcrypt.hashSync(password,12)},${role}) RETURNING id,email,role`;
      const csrf=token(),sid=makeSession(rows[0],csrf);res.setHeader("Set-Cookie",[cookie("la_session",sid)]);return send(res,200,{user:rows[0],csrf});
    }
    if(path==="/api/login"&&method==="POST"){
      if(!allowed("login:"+ip(req),10,600000))return send(res,429,{error:"Too many login attempts"});
      const b=await body(req),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||"");const rows=await sql`SELECT * FROM users WHERE email=${email}`;
      if(!rows.length||!bcrypt.compareSync(password,rows[0].password_hash))return send(res,401,{error:"Invalid email or password"});
      const u={id:rows[0].id,email:rows[0].email,role:rows[0].role},csrf=token(),sid=makeSession(u,csrf);res.setHeader("Set-Cookie",[cookie("la_session",sid)]);return send(res,200,{user:u,csrf});
    }
    if(path==="/api/logout"&&method==="POST"){if(!requireCsrf(req,res))return send(res,403,{error:"CSRF check failed"});res.setHeader("Set-Cookie",cookie("la_session","",0));return send(res,200,{ok:true})}
    if(!user)return send(res,401,{error:"Login required"});
    if(["POST","DELETE"].includes(method)&&!requireCsrf(req,res))return send(res,403,{error:"CSRF check failed"});
    if(path==="/api/categories"&&method==="GET")return send(res,200,{categories});
    if(path==="/api/media"&&method==="GET"){const q=(url.searchParams.get("q")||"").trim(),cat=(url.searchParams.get("category")||"").trim();const rows=cat&&categories.includes(cat)?await sql`SELECT id,title,category,season,quality,url,description,poster,status,last_checked,created_at FROM media WHERE category=${cat} AND (title ILIKE ${"%"+q+"%"} OR description ILIKE ${"%"+q+"%"}) ORDER BY created_at DESC,title`:await sql`SELECT id,title,category,season,quality,url,description,poster,status,last_checked,created_at FROM media WHERE title ILIKE ${"%"+q+"%"} OR description ILIKE ${"%"+q+"%"} ORDER BY created_at DESC,title`;return send(res,200,{media:rows})}
    const m=path.match(/^\/api\/media\/(\d+)$/);
    if(m&&method==="DELETE"){if(user.role!=="admin")return send(res,403,{error:"Admin only"});await sql`DELETE FROM media WHERE id=${Number(m[1])}`;return send(res,200,{ok:true})}
    if(path==="/api/media"&&method==="POST"){if(user.role!=="admin")return send(res,403,{error:"Admin only"});const b=await body(req),title=String(b.title||"").trim(),category=String(b.category||"Other"),u=String(b.url||"").trim();if(!title||title.length>160||!categories.includes(category)||!validUrl(u)||u.length>2048)return send(res,400,{error:"Invalid resource details"});const rows=await sql`INSERT INTO media(title,category,season,quality,url,description,poster) VALUES(${title},${category},${String(b.season||"").slice(0,80)},${String(b.quality||"").slice(0,80)},${u},${String(b.description||"").slice(0,1000)},${String(b.poster||"").slice(0,2048)}) RETURNING id`;return send(res,200,{id:rows[0].id})}
    const c=path.match(/^\/api\/check\/(\d+)$/);if(c&&method==="POST"){if(user.role!=="admin")return send(res,403,{error:"Admin only"});const rows=await sql`SELECT * FROM media WHERE id=${Number(c[1])}`;if(!rows.length)return send(res,404,{error:"Not found"});try{const r=await check(rows[0].url),status=r.ok?"working":"http-"+r.status;await sql`UPDATE media SET status=${status},last_checked=NOW() WHERE id=${rows[0].id}`;return send(res,200,{status})}catch{await sql`UPDATE media SET status='error',last_checked=NOW() WHERE id=${rows[0].id}`;return send(res,200,{status:"error",message:"Link check failed"})}}
    return send(res,404,{error:"Not found"});
  }catch(e){return send(res,500,{error:"Server error"})}
}
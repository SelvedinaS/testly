const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT=__dirname, PUBLIC=path.join(ROOT,'public'), DATA=process.env.DATA_DIR||ROOT;
if(!fs.existsSync(DATA))fs.mkdirSync(DATA,{recursive:true});
const PORT=Number(process.env.PORT||3000);
const JWT_SECRET=process.env.JWT_SECRET||'local-dev-change-this-secret-before-deploy';
const ADMIN_USER=process.env.ADMIN_USER||'admin';
const ADMIN_EMAIL=String(process.env.ADMIN_EMAIL||'admin@testly.local').toLowerCase();
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'admin123';
const ADSENSE_ENABLED=String(process.env.ADSENSE_ENABLED||'false')==='true';
const ADSENSE_CLIENT_ID=process.env.ADSENSE_CLIENT_ID||'';
const ensure=(name,init=[])=>{const p=path.join(DATA,name);if(!fs.existsSync(p))fs.writeFileSync(p,JSON.stringify(init,null,2));};
['users.json','challenges.json','challenge-results.json','favorites.json','events.json'].forEach(n=>ensure(n,[]));
const read=n=>JSON.parse(fs.readFileSync(path.join(DATA,n),'utf8')||'[]');
const write=(n,d)=>fs.writeFileSync(path.join(DATA,n),JSON.stringify(d,null,2));
const send=(res,code,payload,headers={})=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET,POST,PUT,PATCH,DELETE,OPTIONS',...headers});res.end(JSON.stringify(payload));};
const text=(v,max=300)=>String(v??'').replace(/[\u0000-\u001F\u007F]/g,'').trim().slice(0,max);
const now=()=>new Date().toISOString();
const body=req=>new Promise((resolve,reject)=>{let d='';req.on('data',c=>{d+=c;if(d.length>2e6){reject(new Error('Payload too large'));req.destroy();}});req.on('end',()=>{try{resolve(d?JSON.parse(d):{});}catch{reject(new Error('Invalid JSON'));}})});
const b64=v=>Buffer.from(v).toString('base64url');
function signToken(payload){const data=b64(JSON.stringify({...payload,exp:Date.now()+1000*60*60*24*30}));const sig=crypto.createHmac('sha256',JWT_SECRET).update(data).digest('base64url');return data+'.'+sig;}
function verifyToken(token){try{const [data,sig]=String(token||'').split('.');if(!data||!sig)return null;const expected=crypto.createHmac('sha256',JWT_SECRET).update(data).digest('base64url');if(!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected)))return null;const p=JSON.parse(Buffer.from(data,'base64url').toString());if(p.exp<Date.now())return null;return p;}catch{return null;}}
function auth(req){const h=req.headers.authorization||'';return verifyToken(h.startsWith('Bearer ')?h.slice(7):'');}
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){return {salt,hash:crypto.scryptSync(password,salt,64).toString('hex')}}
function checkPassword(password,user){const h=crypto.scryptSync(password,user.salt,64);const d=Buffer.from(user.passwordHash,'hex');return h.length===d.length&&crypto.timingSafeEqual(h,d)}
function rateKey(req,kind){return kind+':' + (req.socket.remoteAddress||'unknown')}
const rates=new Map();
function limited(req,kind,max=20,windowMs=60000){const k=rateKey(req,kind),n=Date.now(),arr=(rates.get(k)||[]).filter(t=>n-t<windowMs);arr.push(n);rates.set(k,arr);return arr.length>max;}
function code(){return crypto.randomBytes(8).toString('base64url').replace(/[-_]/g,'').slice(0,10)}
function sanitizeOptions(arr){return (Array.isArray(arr)?arr:[]).slice(0,6).map(x=>text(x,140)).filter(Boolean)}
function publicChallenge(c){return {code:c.code,title:c.title,type:c.type,language:c.language,ownerName:c.ownerName,questions:c.questions.map(q=>({q:q.q,options:q.options})),createdAt:c.createdAt};}
function serve(req,res){const u=new URL(req.url,'http://x');let pathname=decodeURIComponent(u.pathname);if(pathname==='/'||pathname==='/bs'||pathname==='/en'||/^\/(bs|en)\/(test|quiz|horoskop|zodiac)\//.test(pathname)||/^\/challenge\//.test(pathname)||pathname==='/dashboard') pathname='/index.html';if(pathname==='/admin')pathname='/admin.html';const safe=path.normalize(pathname).replace(/^(\.\.[/\\])+/, '');const file=path.join(PUBLIC,safe);if(!file.startsWith(PUBLIC)||!fs.existsSync(file)||fs.statSync(file).isDirectory())return false;const ext=path.extname(file);const ct={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.txt':'text/plain; charset=utf-8'}[ext]||'application/octet-stream';res.writeHead(200,{'Content-Type':ct,'Cache-Control':ext==='.html'?'no-cache':'public, max-age=3600'});fs.createReadStream(file).pipe(res);return true;}

const server=http.createServer(async(req,res)=>{
  const u=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  try{
    if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET,POST,PUT,PATCH,DELETE,OPTIONS'});return res.end();}
    if(u.pathname==='/'&&req.method==='GET') return send(res,200,{ok:true,name:'Testly API',status:'online'});
    if(u.pathname==='/api/health'&&req.method==='GET') return send(res,200,{ok:true,status:'online',time:now()});
    if(u.pathname==='/api/config'&&req.method==='GET') return send(res,200,{adsenseEnabled:ADSENSE_ENABLED&&!!ADSENSE_CLIENT_ID,adsenseClientId:ADSENSE_ENABLED?ADSENSE_CLIENT_ID:''});
    if(u.pathname==='/api/tests'&&req.method==='GET'){
      const lang=u.searchParams.get('lang');const tests=read('tests.json').filter(t=>t.active!==false);return send(res,200,tests);
    }
    if(u.pathname.startsWith('/api/tests/')&&req.method==='GET'){
      const id=decodeURIComponent(u.pathname.split('/').pop());const t=read('tests.json').find(x=>x.id===id&&x.active!==false);return t?send(res,200,t):send(res,404,{error:'Not found'});
    }
    if(u.pathname==='/api/register'&&req.method==='POST'){
      if(limited(req,'register',8,60000))return send(res,429,{error:'Too many attempts'});
      const b=await body(req),name=text(b.name,60),email=text(b.email,140).toLowerCase(),password=String(b.password||'');
      if(name.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8)return send(res,400,{error:'Provjeri ime, email i lozinku (min. 8 znakova).'});
      const users=read('users.json');if(email===ADMIN_EMAIL||users.some(x=>x.email===email))return send(res,409,{error:'Email je već registrovan.'});
      const h=hashPassword(password),user={id:crypto.randomUUID(),name,email,salt:h.salt,passwordHash:h.hash,status:'active',createdAt:now()};users.push(user);write('users.json',users);const token=signToken({id:user.id,name:user.name,email:user.email,role:'user'});return send(res,201,{token,user:{id:user.id,name:user.name,email:user.email,role:'user'}});
    }
    if(u.pathname==='/api/login'&&req.method==='POST'){
      if(limited(req,'login',12,60000))return send(res,429,{error:'Too many attempts'});
      const b=await body(req),email=text(b.email,140).toLowerCase(),password=String(b.password||'');
      if(email===ADMIN_EMAIL&&password===ADMIN_PASSWORD){
        const admin={id:'admin',name:'Admin',email:ADMIN_EMAIL,role:'admin'};
        return send(res,200,{token:signToken(admin),user:admin});
      }
      const user=read('users.json').find(x=>x.email===email&&x.status!=='disabled');
      if(!user||!checkPassword(password,user))return send(res,401,{error:'Pogrešan email ili lozinka.'});
      const publicUser={id:user.id,name:user.name,email:user.email,role:'user'};
      return send(res,200,{token:signToken(publicUser),user:publicUser});
    }
    if(u.pathname==='/api/me'&&req.method==='GET'){const a=auth(req);return a&&(a.role==='user'||a.role==='admin')?send(res,200,{user:a}):send(res,401,{error:'Unauthorized'});}
    if(u.pathname==='/api/favorites'&&req.method==='GET'){const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Unauthorized'});return send(res,200,{items:read('favorites.json').filter(x=>x.userId===a.id).map(x=>x.testId)});}
    if(u.pathname.startsWith('/api/favorites/')&&(req.method==='POST'||req.method==='DELETE')){const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Unauthorized'});const testId=text(u.pathname.split('/').pop(),80),f=read('favorites.json');const idx=f.findIndex(x=>x.userId===a.id&&x.testId===testId);if(req.method==='POST'&&idx<0)f.push({userId:a.id,testId,createdAt:now()});if(req.method==='DELETE'&&idx>=0)f.splice(idx,1);write('favorites.json',f);return send(res,200,{ok:true});}
    if(u.pathname==='/api/challenges'&&req.method==='POST'){
      const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Login required'});const b=await body(req);const questions=(Array.isArray(b.questions)?b.questions:[]).slice(0,20).map(q=>({q:text(q.q,240),options:sanitizeOptions(q.options),correctIndex:Number.isInteger(q.correctIndex)?q.correctIndex:null})).filter(q=>q.q&&q.options.length>=2&&q.correctIndex>=0&&q.correctIndex<q.options.length);
      if(questions.length<3)return send(res,400,{error:'Dodaj najmanje 3 ispravna pitanja.'});const ch=read('challenges.json');let c;do c=code();while(ch.some(x=>x.code===c));const item={id:crypto.randomUUID(),code:c,userId:a.id,ownerName:a.name,title:text(b.title,100)||'Challenge',type:['know-me','couple','friend','custom'].includes(b.type)?b.type:'custom',language:b.language==='en'?'en':'bs',questions,active:true,plays:0,createdAt:now()};ch.push(item);write('challenges.json',ch);return send(res,201,{code:c,url:`/challenge/${c}`});
    }
    if(/^\/api\/challenges\/[^/]+$/.test(u.pathname)&&req.method==='GET'){
      const c=u.pathname.split('/').pop(),ch=read('challenges.json'),item=ch.find(x=>x.code===c&&x.active!==false);if(!item)return send(res,404,{error:'Challenge not found'});item.plays=(item.plays||0)+1;write('challenges.json',ch);return send(res,200,{challenge:publicChallenge(item)});
    }
    if(/^\/api\/challenges\/[^/]+\/submit$/.test(u.pathname)&&req.method==='POST'){
      const c=u.pathname.split('/')[3],b=await body(req),ch=read('challenges.json'),item=ch.find(x=>x.code===c&&x.active!==false);if(!item)return send(res,404,{error:'Challenge not found'});const answers=Array.isArray(b.answers)?b.answers:[];let score=0;item.questions.forEach((q,i)=>{if(Number(answers[i])===q.correctIndex)score++});const playerName=text(b.playerName,60)||'Gost';const rs=read('challenge-results.json');rs.push({id:crypto.randomUUID(),challengeId:item.id,code:item.code,userId:item.userId,playerName,score,total:item.questions.length,percent:Math.round(score/item.questions.length*100),createdAt:now()});write('challenge-results.json',rs);return send(res,201,{score,total:item.questions.length,percent:Math.round(score/item.questions.length*100)});
    }
    if(u.pathname==='/api/my/challenges'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Unauthorized'});const ch=read('challenges.json').filter(x=>x.userId===a.id),rs=read('challenge-results.json');return send(res,200,{items:ch.map(x=>({...x,questions:undefined,results:rs.filter(r=>r.challengeId===x.id).sort((a,b)=>b.percent-a.percent||a.createdAt.localeCompare(b.createdAt))}))});
    }
    if(/^\/api\/my\/challenges\/[^/]+$/.test(u.pathname)&&(req.method==='DELETE'||req.method==='PATCH')){
      const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Unauthorized'});const id=u.pathname.split('/').pop(),ch=read('challenges.json'),item=ch.find(x=>x.id===id&&x.userId===a.id);if(!item)return send(res,404,{error:'Not found'});if(req.method==='DELETE'){const next=ch.filter(x=>x.id!==id);write('challenges.json',next);write('challenge-results.json',read('challenge-results.json').filter(x=>x.challengeId!==id));}else{const b=await body(req);item.active=b.active!==false;write('challenges.json',ch);}return send(res,200,{ok:true});
    }
    if(u.pathname==='/api/events'&&req.method==='POST'){const b=await body(req),ev=read('events.json');ev.push({id:crypto.randomUUID(),event:text(b.event,60),testId:text(b.testId,80),language:b.language==='en'?'en':'bs',createdAt:now()});if(ev.length>10000)ev.splice(0,ev.length-10000);write('events.json',ev);return send(res,201,{ok:true});}
    if(u.pathname==='/api/admin/login'&&req.method==='POST'){
      if(limited(req,'admin',10,60000))return send(res,429,{error:'Too many attempts'});const b=await body(req);if(text(b.username,80)!==ADMIN_USER||String(b.password||'')!==ADMIN_PASSWORD)return send(res,401,{error:'Wrong credentials'});return send(res,200,{token:signToken({id:'admin',name:'Admin',role:'admin'})});
    }
    if(u.pathname==='/api/admin/stats'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});const users=read('users.json'),ch=read('challenges.json'),rs=read('challenge-results.json'),ev=read('events.json'),tests=read('tests.json');const since=Date.now()-7*86400000;const byEvent={};ev.forEach(x=>byEvent[x.event]=(byEvent[x.event]||0)+1);return send(res,200,{users:users.length,newUsers7d:users.filter(x=>Date.parse(x.createdAt)>since).length,tests:tests.filter(x=>x.active!==false).length,challenges:ch.length,challengePlays:ch.reduce((s,x)=>s+(x.plays||0),0),challengeResults:rs.length,events:byEvent,bsViews:ev.filter(x=>x.language==='bs'&&x.event==='page_view').length,enViews:ev.filter(x=>x.language==='en'&&x.event==='page_view').length});
    }
    if(u.pathname==='/api/admin/users'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const items=read('users.json').map(x=>({id:x.id,name:x.name,email:x.email,status:x.status||'active',createdAt:x.createdAt}));
      return send(res,200,{items});
    }
    if(u.pathname==='/api/admin/tests'&&req.method==='GET'){const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});return send(res,200,{items:read('tests.json')});}
    if(u.pathname==='/api/admin/tests'&&req.method==='POST'){const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});const b=await body(req);const tests=read('tests.json');const id=text(b.id,80)||('quiz-'+crypto.randomBytes(5).toString('hex'));if(tests.some(x=>x.id===id))return send(res,409,{error:'ID already exists'});const item={...b,id,active:b.active!==false,featured:!!b.featured,createdAt:now()};if(!item.title?.bs||!item.title?.en||!Array.isArray(item.questions)||item.questions.length<1||!Array.isArray(item.results)||item.results.length<1)return send(res,400,{error:'Test must have BS/EN title, questions and results'});tests.push(item);write('tests.json',tests);return send(res,201,{ok:true,test:item});}
    if(/^\/api\/admin\/tests\/[^/]+$/.test(u.pathname)&&req.method==='PUT'){const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});const id=u.pathname.split('/').pop(),tests=read('tests.json'),idx=tests.findIndex(x=>x.id===id);if(idx<0)return send(res,404,{error:'Not found'});const b=await body(req);const item={...tests[idx],...b,id:tests[idx].id};if(!item.title?.bs||!item.title?.en||!Array.isArray(item.questions)||!Array.isArray(item.results))return send(res,400,{error:'Invalid quiz'});tests[idx]=item;write('tests.json',tests);return send(res,200,{ok:true,test:item});}
    if(/^\/api\/admin\/tests\/[^/]+$/.test(u.pathname)&&req.method==='DELETE'){const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});const id=u.pathname.split('/').pop(),tests=read('tests.json');const next=tests.filter(x=>x.id!==id);if(next.length===tests.length)return send(res,404,{error:'Not found'});write('tests.json',next);return send(res,200,{ok:true});}
    if(/^\/api\/admin\/tests\/[^/]+$/.test(u.pathname)&&req.method==='PATCH'){const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});const id=u.pathname.split('/').pop(),tests=read('tests.json'),t=tests.find(x=>x.id===id);if(!t)return send(res,404,{error:'Not found'});const b=await body(req);if(typeof b.active==='boolean')t.active=b.active;if(typeof b.featured==='boolean')t.featured=b.featured;write('tests.json',tests);return send(res,200,{ok:true,test:t});}
    if(u.pathname==='/api/admin/challenges'&&req.method==='GET'){const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});const lang=u.searchParams.get('lang');return send(res,200,{items:read('challenges.json').filter(x=>!lang||x.language===lang).map(x=>({id:x.id,code:x.code,title:x.title,type:x.type,ownerName:x.ownerName,language:x.language,plays:x.plays,active:x.active,createdAt:x.createdAt}))});}
    if(/^\/api\/admin\/challenges\/[^/]+$/.test(u.pathname)&&req.method==='DELETE'){const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});const id=u.pathname.split('/').pop(),ch=read('challenges.json'),item=ch.find(x=>x.id===id);if(!item)return send(res,404,{error:'Not found'});item.active=false;write('challenges.json',ch);return send(res,200,{ok:true});}
    if(serve(req,res))return;return send(res,404,{error:'Not found'});
  }catch(e){console.error(e);return send(res,500,{error:'Server error'});}
});
server.listen(PORT,()=>console.log(`Testly Launch running at http://localhost:${PORT}`));

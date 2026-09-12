const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const ROOT=__dirname;
const PORT=Number(process.env.PORT||3000);
const JWT_SECRET=process.env.JWT_SECRET||'local-dev-change-this-secret-before-deploy';
const ADMIN_USER=process.env.ADMIN_USER||'admin';
const ADMIN_EMAIL=String(process.env.ADMIN_EMAIL||'admin@testly.local').toLowerCase();
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'admin123';
const ADSENSE_ENABLED=String(process.env.ADSENSE_ENABLED||'false')==='true';
const ADSENSE_CLIENT_ID=process.env.ADSENSE_CLIENT_ID||'';
const MONGODB_URI=String(process.env.MONGODB_URI||'').trim();
const MONGODB_DB=String(process.env.MONGODB_DB||'testly').trim()||'testly';

if(!MONGODB_URI){
  console.error('Missing MONGODB_URI environment variable.');
  process.exit(1);
}

const send=(res,code,payload,headers={})=>{
  res.writeHead(code,{
    'Content-Type':'application/json; charset=utf-8',
    'Access-Control-Allow-Origin':'*',
    'Access-Control-Allow-Headers':'Content-Type, Authorization',
    'Access-Control-Allow-Methods':'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    ...headers
  });
  res.end(JSON.stringify(payload));
};
const text=(v,max=300)=>String(v??'').replace(/[\u0000-\u001F\u007F]/g,'').trim().slice(0,max);
const now=()=>new Date().toISOString();
const body=req=>new Promise((resolve,reject)=>{
  let d='';
  req.on('data',c=>{d+=c;if(d.length>2e6){reject(new Error('Payload too large'));req.destroy();}});
  req.on('end',()=>{try{resolve(d?JSON.parse(d):{});}catch{reject(new Error('Invalid JSON'));}});
});
const b64=v=>Buffer.from(v).toString('base64url');
function signToken(payload){
  const data=b64(JSON.stringify({...payload,exp:Date.now()+1000*60*60*24*30}));
  const sig=crypto.createHmac('sha256',JWT_SECRET).update(data).digest('base64url');
  return data+'.'+sig;
}
function verifyToken(token){
  try{
    const [data,sig]=String(token||'').split('.');
    if(!data||!sig)return null;
    const expected=crypto.createHmac('sha256',JWT_SECRET).update(data).digest('base64url');
    const a=Buffer.from(sig),b=Buffer.from(expected);
    if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;
    const p=JSON.parse(Buffer.from(data,'base64url').toString());
    if(p.exp<Date.now())return null;
    return p;
  }catch{return null;}
}
function auth(req){
  const h=req.headers.authorization||'';
  return verifyToken(h.startsWith('Bearer ')?h.slice(7):'');
}
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){
  return {salt,hash:crypto.scryptSync(password,salt,64).toString('hex')};
}
function checkPassword(password,user){
  try{
    const h=crypto.scryptSync(password,user.salt,64);
    const d=Buffer.from(user.passwordHash,'hex');
    return h.length===d.length&&crypto.timingSafeEqual(h,d);
  }catch{return false;}
}
function rateKey(req,kind){return kind+':' + (req.socket.remoteAddress||'unknown');}
const rates=new Map();
function limited(req,kind,max=20,windowMs=60000){
  const k=rateKey(req,kind),n=Date.now(),arr=(rates.get(k)||[]).filter(t=>n-t<windowMs);
  arr.push(n);rates.set(k,arr);return arr.length>max;
}
function code(){return crypto.randomBytes(8).toString('base64url').replace(/[-_]/g,'').slice(0,10);}
function sanitizeOptions(arr){return (Array.isArray(arr)?arr:[]).slice(0,6).map(x=>text(x,140)).filter(Boolean);}
function publicChallenge(c){
  return {code:c.code,title:c.title,type:c.type,language:c.language,ownerName:c.ownerName,
    questions:c.questions.map(q=>({q:q.q,options:q.options})),createdAt:c.createdAt};
}

let db, users, challenges, results, favorites, events, tests, visitors;

async function initDb(){
  const client=new MongoClient(MONGODB_URI,{maxPoolSize:20});
  await client.connect();
  db=client.db(MONGODB_DB);
  users=db.collection('users');
  challenges=db.collection('challenges');
  results=db.collection('challengeResults');
  favorites=db.collection('favorites');
  events=db.collection('events');
  tests=db.collection('tests');
  visitors=db.collection('visitors');

  await Promise.all([
    users.createIndex({email:1},{unique:true}),
    challenges.createIndex({code:1},{unique:true}),
    challenges.createIndex({userId:1}),
    results.createIndex({challengeId:1}),
    results.createIndex({attemptId:1},{unique:true,sparse:true}),
    favorites.createIndex({userId:1,testId:1},{unique:true}),
    events.createIndex({createdAt:1}),
    events.createIndex({event:1,createdAt:-1}),
    events.createIndex({contentId:1,event:1}),
    visitors.createIndex({visitorId:1},{unique:true}),
    visitors.createIndex({lastSeen:-1}),
    visitors.createIndex({userId:1}),
    tests.createIndex({id:1},{unique:true})
  ]);

  const testCount=await tests.countDocuments();
  if(testCount===0){
    const seedPath=path.join(ROOT,'tests.json');
    if(fs.existsSync(seedPath)){
      const seed=JSON.parse(fs.readFileSync(seedPath,'utf8')||'[]');
      if(seed.length) await tests.insertMany(seed);
      console.log(`Seeded ${seed.length} tests into MongoDB.`);
    }
  }
  console.log(`MongoDB connected: ${MONGODB_DB}`);
}


function clientIp(req){
  const f=String(req.headers['x-forwarded-for']||'').split(',')[0].trim();
  return f||String(req.socket.remoteAddress||'').replace(/^::ffff:/,'');
}
function publicIp(ip){
  if(!ip)return false;
  return !/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd)/i.test(ip);
}
async function lookupCountry(ip){
  if(!publicIp(ip))return {country:'Unknown',countryCode:''};
  try{
    const r=await fetch('https://ipwho.is/'+encodeURIComponent(ip)+'?fields=success,country,country_code',{signal:AbortSignal.timeout(2200)});
    const d=await r.json();
    if(d&&d.success!==false&&d.country)return {country:text(d.country,80),countryCode:text(d.country_code,8)};
  }catch{}
  return {country:'Unknown',countryCode:''};
}
function completionEventName(e){return ['quiz_complete','solo_complete','zodiac_complete','game_complete','challenge_complete'].includes(e)}
function startEventName(e){return ['quiz_start','solo_start','zodiac_start','game_start','challenge_start'].includes(e)}
function safeSource(v){return text(v||'Direct',100)||'Direct'}

const server=http.createServer(async(req,res)=>{
  const u=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  try{
    if(req.method==='OPTIONS'){
      res.writeHead(204,{
        'Access-Control-Allow-Origin':'*',
        'Access-Control-Allow-Headers':'Content-Type, Authorization',
        'Access-Control-Allow-Methods':'GET,POST,PUT,PATCH,DELETE,OPTIONS'
      });
      return res.end();
    }
    if(u.pathname==='/'&&req.method==='GET')return send(res,200,{ok:true,name:'Testly API',status:'online',database:'mongodb'});
    if(u.pathname==='/api/health'&&req.method==='GET'){
      await db.command({ping:1});
      return send(res,200,{ok:true,status:'online',database:'mongodb',time:now()});
    }
    if(u.pathname==='/api/config'&&req.method==='GET')
      return send(res,200,{adsenseEnabled:ADSENSE_ENABLED&&!!ADSENSE_CLIENT_ID,adsenseClientId:ADSENSE_ENABLED?ADSENSE_CLIENT_ID:''});

    if(u.pathname==='/api/tests'&&req.method==='GET'){
      return send(res,200,await tests.find({active:{$ne:false}},{projection:{_id:0}}).toArray());
    }
    if(u.pathname.startsWith('/api/tests/')&&req.method==='GET'){
      const id=decodeURIComponent(u.pathname.split('/').pop());
      const t=await tests.findOne({id,active:{$ne:false}},{projection:{_id:0}});
      return t?send(res,200,t):send(res,404,{error:'Not found'});
    }

    if(u.pathname==='/api/register'&&req.method==='POST'){
      if(limited(req,'register',8,60000))return send(res,429,{error:'Too many attempts'});
      const b=await body(req),name=text(b.name,60),email=text(b.email,140).toLowerCase(),password=String(b.password||'');
      if(name.length<2||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8)
        return send(res,400,{error:'Provjeri ime, email i lozinku (min. 8 znakova).'});
      if(email===ADMIN_EMAIL||await users.findOne({email}))return send(res,409,{error:'Email je već registrovan.'});
      const h=hashPassword(password),user={id:crypto.randomUUID(),name,email,salt:h.salt,passwordHash:h.hash,status:'active',createdAt:now(),lastLoginAt:now(),lastSeenAt:now()};
      await users.insertOne(user);
      const publicUser={id:user.id,name:user.name,email:user.email,role:'user'};
      return send(res,201,{token:signToken(publicUser),user:publicUser});
    }

    if(u.pathname==='/api/login'&&req.method==='POST'){
      if(limited(req,'login',12,60000))return send(res,429,{error:'Too many attempts'});
      const b=await body(req),email=text(b.email,140).toLowerCase(),password=String(b.password||'');
      if(email===ADMIN_EMAIL&&password===ADMIN_PASSWORD){
        const admin={id:'admin',name:'Admin',email:ADMIN_EMAIL,role:'admin'};
        return send(res,200,{token:signToken(admin),user:admin});
      }
      const user=await users.findOne({email,status:{$ne:'disabled'}});
      if(!user||!checkPassword(password,user))return send(res,401,{error:'Pogrešan email ili lozinka.'});
      await users.updateOne({id:user.id},{$set:{lastLoginAt:now(),lastSeenAt:now()}});
      const publicUser={id:user.id,name:user.name,email:user.email,role:'user'};
      return send(res,200,{token:signToken(publicUser),user:publicUser});
    }

    if(u.pathname==='/api/me'&&req.method==='GET'){
      const a=auth(req);
      return a&&(a.role==='user'||a.role==='admin')?send(res,200,{user:a}):send(res,401,{error:'Unauthorized'});
    }

    if(u.pathname==='/api/favorites'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Unauthorized'});
      const items=await favorites.find({userId:a.id},{projection:{_id:0,testId:1}}).toArray();
      return send(res,200,{items:items.map(x=>x.testId)});
    }
    if(u.pathname.startsWith('/api/favorites/')&&(req.method==='POST'||req.method==='DELETE')){
      const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Unauthorized'});
      const testId=text(u.pathname.split('/').pop(),80);
      if(req.method==='POST'){
        await favorites.updateOne({userId:a.id,testId},{$setOnInsert:{userId:a.id,testId,createdAt:now()}},{upsert:true});
      }else await favorites.deleteOne({userId:a.id,testId});
      return send(res,200,{ok:true});
    }

    if(u.pathname==='/api/challenges'&&req.method==='POST'){
      const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Login required'});
      const b=await body(req);
      const questions=(Array.isArray(b.questions)?b.questions:[]).slice(0,20).map(q=>({
        q:text(q.q,240),options:sanitizeOptions(q.options),
        correctIndex:Number.isInteger(q.correctIndex)?q.correctIndex:null
      })).filter(q=>q.q&&q.options.length>=2&&q.correctIndex>=0&&q.correctIndex<q.options.length);
      if(questions.length<3)return send(res,400,{error:'Dodaj najmanje 3 ispravna pitanja.'});
      let c;do c=code();while(await challenges.findOne({code:c}));
      const item={id:crypto.randomUUID(),code:c,userId:a.id,ownerName:a.name,title:text(b.title,100)||'Challenge',
        type:['know-me','couple','friend','custom'].includes(b.type)?b.type:'custom',
        language:b.language==='en'?'en':'bs',questions,active:true,plays:0,createdAt:now()};
      await challenges.insertOne(item);
      return send(res,201,{code:c,url:`/challenge/${c}`});
    }

    if(/^\/api\/challenges\/[^/]+$/.test(u.pathname)&&req.method==='GET'){
      const c=u.pathname.split('/').pop();
      const item=await challenges.findOne({code:c,active:{$ne:false}});
      if(!item)return send(res,404,{error:'Challenge not found'});
      await challenges.updateOne({id:item.id},{$inc:{plays:1}});
      item.plays=(item.plays||0)+1;
      return send(res,200,{challenge:publicChallenge(item)});
    }

    if(/^\/api\/challenges\/[^/]+\/submit$/.test(u.pathname)&&req.method==='POST'){
      if(limited(req,'challenge-submit',60,60000))return send(res,429,{error:'Too many attempts'});
      const c=u.pathname.split('/')[3],b=await body(req);
      const item=await challenges.findOne({code:c,active:{$ne:false}});
      if(!item)return send(res,404,{error:'Challenge not found'});
      const answers=Array.isArray(b.answers)?b.answers.map(Number):[];
      if(answers.length!==item.questions.length||answers.some((v,i)=>!Number.isInteger(v)||v<0||v>=item.questions[i].options.length))
        return send(res,400,{error:'Incomplete or invalid answers'});
      const attemptId=text(b.attemptId,120)||crypto.randomUUID();
      const existing=await results.findOne({attemptId});
      if(existing)return send(res,200,{score:existing.score,total:existing.total,percent:existing.percent,duplicate:true});
      let score=0;item.questions.forEach((q,i)=>{if(answers[i]===q.correctIndex)score++;});
      const playerName=text(b.playerName,60)||'Gost';
      const result={id:crypto.randomUUID(),attemptId,challengeId:item.id,code:item.code,userId:item.userId,playerName,score,
        total:item.questions.length,percent:Math.round(score/item.questions.length*100),createdAt:now()};
      await results.insertOne(result);
      const visitor=text(b.visitorId,120);
      let country='Unknown',countryCode='';
      const vv=visitor?await visitors.findOne({visitorId:visitor}):null;
      if(vv){country=vv.country||country;countryCode=vv.countryCode||'';}
      await events.insertOne({id:crypto.randomUUID(),event:'challenge_complete',visitorId:visitor,contentId:item.code,contentType:'challenge',
        titleBs:item.title,titleEn:item.title,score:result.percent,resultTitle:'',language:item.language,source:safeSource(b.source),referrer:'',page:'/challenge/'+item.code,
        timezone:'',screenWidth:0,country,countryCode,isRegistered:false,userId:'',userName:playerName,userEmail:'',createdAt:now()});
      if(visitor)await visitors.updateOne({visitorId},{$set:{lastSeen:now(),lastLanguage:item.language,lastSource:safeSource(b.source)},$inc:{testsCompleted:1}},{upsert:false});
      return send(res,201,{score,total:item.questions.length,percent:result.percent});
    }

    if(u.pathname==='/api/my/challenges'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Unauthorized'});
      const ch=await challenges.find({userId:a.id},{projection:{_id:0}}).toArray();
      const ids=ch.map(x=>x.id);
      const rs=ids.length?await results.find({challengeId:{$in:ids}},{projection:{_id:0}}).toArray():[];
      const items=ch.map(x=>({...x,questions:undefined,results:rs.filter(r=>r.challengeId===x.id)
        .sort((a,b)=>b.percent-a.percent||a.createdAt.localeCompare(b.createdAt))}));
      return send(res,200,{items});
    }

    if(/^\/api\/my\/challenges\/[^/]+$/.test(u.pathname)&&(req.method==='DELETE'||req.method==='PATCH')){
      const a=auth(req);if(!a||a.role!=='user')return send(res,401,{error:'Unauthorized'});
      const id=u.pathname.split('/').pop();
      const item=await challenges.findOne({id,userId:a.id});
      if(!item)return send(res,404,{error:'Not found'});
      if(req.method==='DELETE'){
        await Promise.all([challenges.deleteOne({id,userId:a.id}),results.deleteMany({challengeId:id})]);
      }else{
        const b=await body(req);await challenges.updateOne({id,userId:a.id},{$set:{active:b.active!==false}});
      }
      return send(res,200,{ok:true});
    }

    if(u.pathname==='/api/events'&&req.method==='POST'){
      const b=await body(req);
      const visitorId=text(b.visitorId,120);
      if(!visitorId)return send(res,400,{error:'Missing visitorId'});
      const a=auth(req);
      const eventName=text(b.event,60);
      const existing=await visitors.findOne({visitorId});
      let country=existing?.country||'';
      let countryCode=existing?.countryCode||'';
      if(!country||country==='Unknown'){
        const geo=await lookupCountry(clientIp(req));
        country=geo.country;countryCode=geo.countryCode;
      }
      const createdAt=now();
      let userInfo={isRegistered:false,userId:'',userName:'',userEmail:''};
      if(a&&a.role==='user'){
        userInfo={isRegistered:true,userId:a.id,userName:text(a.name,80),userEmail:text(a.email,140)};
        await users.updateOne({id:a.id},{$set:{lastSeenAt:createdAt}});
      }
      const item={
        id:crypto.randomUUID(),event:eventName,visitorId,
        contentId:text(b.contentId||b.testId,120),contentType:text(b.contentType,40),
        titleBs:text(b.titleBs,180),titleEn:text(b.titleEn,180),
        score:(b.score===null||b.score===undefined||b.score==='')?null:Number(b.score),
        resultTitle:text(b.resultTitle,180),language:b.language==='en'?'en':'bs',
        source:safeSource(b.source),referrer:text(b.referrer,140),page:text(b.page,200),
        timezone:text(b.timezone,80),screenWidth:Number(b.screenWidth||0)||0,
        country,countryCode,...userInfo,createdAt
      };
      await events.insertOne(item);

      const inc={pageViews:eventName==='page_view'?1:0,testsCompleted:completionEventName(eventName)&&eventName!=='game_complete'?1:0,gamesCompleted:eventName==='game_complete'?1:0};
      const set={
        lastSeen:createdAt,lastLanguage:item.language,lastSource:item.source,lastPage:item.page,country,countryCode,
        timezone:item.timezone,screenWidth:item.screenWidth,...userInfo
      };
      const setOnInsert={visitorId,firstSeen:createdAt,firstSource:item.source};
      await visitors.updateOne({visitorId},{$set:set,$setOnInsert:setOnInsert,$inc:inc},{upsert:true});

      const count=await events.estimatedDocumentCount();
      if(count>50000){
        const old=await events.find({}).sort({createdAt:1}).limit(count-45000).project({_id:1}).toArray();
        if(old.length)await events.deleteMany({_id:{$in:old.map(x=>x._id)}});
      }
      return send(res,201,{ok:true});
    }

    if(u.pathname==='/api/admin/login'&&req.method==='POST'){
      if(limited(req,'admin',10,60000))return send(res,429,{error:'Too many attempts'});
      const b=await body(req);
      if(text(b.username,80)!==ADMIN_USER||String(b.password||'')!==ADMIN_PASSWORD)return send(res,401,{error:'Wrong credentials'});
      return send(res,200,{token:signToken({id:'admin',name:'Admin',email:ADMIN_EMAIL,role:'admin'})});
    }

    if(u.pathname==='/api/admin/stats'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const n=Date.now(),today=new Date();today.setHours(0,0,0,0);
      const since7=new Date(n-7*86400000).toISOString(),onlineSince=new Date(n-5*60000).toISOString();
      const completionNames=['quiz_complete','solo_complete','zodiac_complete','game_complete','challenge_complete'];
      const [uniqueVisitors,registeredVisitors,onlineNow,totalCompletions,completionsToday,completions7d,pageViews,userCount,newUsers7d,testCount,challengeCount,challengeResultCount,ch] = await Promise.all([
        visitors.countDocuments(),visitors.countDocuments({isRegistered:true}),visitors.countDocuments({lastSeen:{$gte:onlineSince}}),
        events.countDocuments({event:{$in:completionNames}}),events.countDocuments({event:{$in:completionNames},createdAt:{$gte:today.toISOString()}}),
        events.countDocuments({event:{$in:completionNames},createdAt:{$gte:since7}}),events.countDocuments({event:'page_view'}),
        users.countDocuments(),users.countDocuments({createdAt:{$gte:since7}}),tests.countDocuments({active:{$ne:false}}),
        challenges.countDocuments(),results.countDocuments(),challenges.find({},{projection:{_id:0,plays:1}}).toArray()
      ]);
      return send(res,200,{uniqueVisitors,registeredVisitors,guestVisitors:Math.max(0,uniqueVisitors-registeredVisitors),onlineNow,totalCompletions,completionsToday,completions7d,pageViews,
        users:userCount,newUsers7d,tests:testCount,challenges:challengeCount,challengeResults:challengeResultCount,challengePlays:ch.reduce((s,x)=>s+(x.plays||0),0)});
    }

    if(u.pathname==='/api/admin/analytics'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const completionNames=['quiz_complete','solo_complete','zodiac_complete','game_complete'];
      const startNames=['quiz_start','solo_start','zodiac_start','game_start'];
      const [countriesRaw,sourcesRaw,languagesRaw,compRaw,startRaw]=await Promise.all([
        visitors.aggregate([{$group:{_id:{$ifNull:['$country','Unknown']},count:{$sum:1}}},{$sort:{count:-1}},{$limit:12}]).toArray(),
        visitors.aggregate([{$group:{_id:{$ifNull:['$firstSource','Direct']},count:{$sum:1}}},{$sort:{count:-1}},{$limit:12}]).toArray(),
        events.aggregate([{$match:{event:'page_view'}},{$group:{_id:'$language',count:{$sum:1}}},{$sort:{count:-1}}]).toArray(),
        events.aggregate([{$match:{event:{$in:completionNames}}},{$group:{_id:{contentId:'$contentId',contentType:'$contentType',titleBs:'$titleBs',titleEn:'$titleEn'},completions:{$sum:1}}}]).toArray(),
        events.aggregate([{$match:{event:{$in:startNames}}},{$group:{_id:{contentId:'$contentId'},starts:{$sum:1}}}]).toArray()
      ]);
      const startMap=new Map(startRaw.map(x=>[x._id.contentId,x.starts]));
      const popular=compRaw.map(x=>({contentId:x._id.contentId,contentType:x._id.contentType,titleBs:x._id.titleBs,titleEn:x._id.titleEn,
        starts:startMap.get(x._id.contentId)||0,completions:x.completions})).sort((x,y)=>y.completions-x.completions||y.starts-x.starts).slice(0,20);
      return send(res,200,{
        countries:countriesRaw.map(x=>({name:x._id||'Unknown',count:x.count})),
        sources:sourcesRaw.map(x=>({name:x._id||'Direct',count:x.count})),
        languages:languagesRaw.map(x=>({name:String(x._id||'').toUpperCase()||'?',count:x.count})),
        popular
      });
    }

    if(u.pathname==='/api/admin/visitors'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const limit=Math.min(500,Math.max(1,Number(u.searchParams.get('limit')||250)));
      const onlineSince=new Date(Date.now()-5*60000).toISOString();
      const items=await visitors.find({},{projection:{_id:0}}).sort({lastSeen:-1}).limit(limit).toArray();
      items.forEach(x=>x.online=!!x.lastSeen&&x.lastSeen>=onlineSince);
      return send(res,200,{items});
    }

    if(u.pathname==='/api/admin/completions'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const limit=Math.min(500,Math.max(1,Number(u.searchParams.get('limit')||250)));
      const names=['quiz_complete','solo_complete','zodiac_complete','game_complete','challenge_complete'];
      const items=await events.find({event:{$in:names}},{projection:{_id:0}}).sort({createdAt:-1}).limit(limit).toArray();
      return send(res,200,{items});
    }

    if(u.pathname==='/api/admin/users'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const items=await users.find({},{projection:{_id:0,id:1,name:1,email:1,status:1,createdAt:1,lastLoginAt:1,lastSeenAt:1}}).sort({createdAt:-1}).toArray();
      return send(res,200,{items});
    }

    if(u.pathname==='/api/admin/tests'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      return send(res,200,{items:await tests.find({},{projection:{_id:0}}).toArray()});
    }
    if(u.pathname==='/api/admin/tests'&&req.method==='POST'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const b=await body(req),id=text(b.id,80)||('quiz-'+crypto.randomBytes(5).toString('hex'));
      if(await tests.findOne({id}))return send(res,409,{error:'ID already exists'});
      const item={...b,id,active:b.active!==false,featured:!!b.featured,createdAt:now()};
      if(!item.title?.bs||!item.title?.en||!Array.isArray(item.questions)||item.questions.length<1||!Array.isArray(item.results)||item.results.length<1)
        return send(res,400,{error:'Test must have BS/EN title, questions and results'});
      await tests.insertOne(item);delete item._id;
      return send(res,201,{ok:true,test:item});
    }
    if(/^\/api\/admin\/tests\/[^/]+$/.test(u.pathname)&&req.method==='PUT'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const id=u.pathname.split('/').pop(),old=await tests.findOne({id});
      if(!old)return send(res,404,{error:'Not found'});
      const b=await body(req),item={...old,...b,id:old.id};delete item._id;
      if(!item.title?.bs||!item.title?.en||!Array.isArray(item.questions)||!Array.isArray(item.results))
        return send(res,400,{error:'Invalid quiz'});
      await tests.replaceOne({id},item);
      return send(res,200,{ok:true,test:item});
    }
    if(/^\/api\/admin\/tests\/[^/]+$/.test(u.pathname)&&req.method==='DELETE'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const id=u.pathname.split('/').pop(),r=await tests.deleteOne({id});
      return r.deletedCount?send(res,200,{ok:true}):send(res,404,{error:'Not found'});
    }
    if(/^\/api\/admin\/tests\/[^/]+$/.test(u.pathname)&&req.method==='PATCH'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const id=u.pathname.split('/').pop(),b=await body(req),set={};
      if(typeof b.active==='boolean')set.active=b.active;if(typeof b.featured==='boolean')set.featured=b.featured;
      const r=await tests.findOneAndUpdate({id},{$set:set},{returnDocument:'after',projection:{_id:0}});
      const t=r&&r.value!==undefined?r.value:r;
      return t?send(res,200,{ok:true,test:t}):send(res,404,{error:'Not found'});
    }

    if(u.pathname==='/api/admin/challenges'&&req.method==='GET'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const lang=u.searchParams.get('lang'),q=lang?{language:lang}:{};
      const items=await challenges.find(q,{projection:{_id:0,questions:0,userId:0}}).sort({createdAt:-1}).toArray();
      return send(res,200,{items});
    }
    if(/^\/api\/admin\/challenges\/[^/]+$/.test(u.pathname)&&req.method==='DELETE'){
      const a=auth(req);if(!a||a.role!=='admin')return send(res,401,{error:'Unauthorized'});
      const id=u.pathname.split('/').pop(),r=await challenges.updateOne({id},{$set:{active:false}});
      return r.matchedCount?send(res,200,{ok:true}):send(res,404,{error:'Not found'});
    }

    return send(res,404,{error:'Not found'});
  }catch(e){
    console.error(e);
    if(e&&e.code===11000)return send(res,409,{error:'Already exists'});
    return send(res,500,{error:'Server error'});
  }
});

initDb().then(()=>{
  server.listen(PORT,()=>console.log(`Testly API running on port ${PORT}`));
}).catch(err=>{
  console.error('MongoDB startup error:',err);
  process.exit(1);
});

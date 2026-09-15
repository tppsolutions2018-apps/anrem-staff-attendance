const path=require('path');
const express=require('express');
const helmet=require('helmet');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const {Pool}=require('pg');

const PORT=Number(process.env.PORT||3000);
const JWT_SECRET=process.env.JWT_SECRET||'';
const ADMIN_USER=String(process.env.ADMIN_USER||'admin').trim().toLowerCase();
const ADMIN_PASS=String(process.env.ADMIN_PASS||'');
const DATABASE_URL=String(process.env.DATABASE_URL||'').trim();
if(!JWT_SECRET||JWT_SECRET.length<32) throw new Error('JWT_SECRET must be set to a random value of at least 32 characters.');
if(!ADMIN_PASS||ADMIN_PASS.length<8) throw new Error('ADMIN_PASS must be set and be at least 8 characters.');
if(!DATABASE_URL) throw new Error('DATABASE_URL must be set to a Render PostgreSQL connection string.');

const pool=new Pool({connectionString:DATABASE_URL,max:10,idleTimeoutMillis:30000});

function normalizeRole(r){const s=String(r||'').trim().toLowerCase();return s==='teacher'||s==='staff'?'Staff':s==='admin'||s==='administrator'?'Admin':s==='student'?'Student':r}
function safeUser(u){if(!u||typeof u!=='object')return null;const x=Object.assign({},u);delete x.password;delete x.loginPassword;delete x.staffPassword;return x}
function stripPerson(p){if(!p||typeof p!=='object')return p;const x=Object.assign({},p);delete x.loginPassword;delete x.staffPassword;return x}
function issue(user){return jwt.sign({username:user.username,role:user.role,uid:user.uid||null},JWT_SECRET,{expiresIn:'12h'})}
function auth(req,res,next){const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'Login required'});try{req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}catch{return res.status(401).json({error:'Session expired'})}}
function adminOnly(req,res,next){if(req.user.role!=='Admin')return res.status(403).json({error:'Admin only'});next()}

async function getSnapshot(key,def=[]){
  const r=await pool.query('SELECT value FROM snapshots WHERE key=$1',[key]);
  return r.rowCount? (r.rows[0].value ?? def) : def;
}
async function saveSnapshot(key,value){
  await pool.query(`INSERT INTO snapshots(key,value) VALUES($1,$2::jsonb)
    ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,[key,JSON.stringify(value)]);
}
async function getAllAttendance(){
  const r=await pool.query('SELECT payload FROM attendance ORDER BY created_at ASC');
  return r.rows.map(x=>x.payload);
}
async function sanitizeStateFor(user){
  const people=await getSnapshot('rcs_people',[]);
  const allUsers=await getSnapshot('rcs_users',[]);
  const isAdmin=user.role==='Admin';
  if(isAdmin){
    return {
      rcs_people:(Array.isArray(people)?people:[]).filter(Boolean).map(stripPerson),
      rcs_users:(Array.isArray(allUsers)?allUsers:[]).filter(Boolean).map(safeUser),
      rcs_greports:await getSnapshot('rcs_greports',[]),
      rcs_att:await getAllAttendance()
    };
  }
  const uid=String(user.uid||'');
  const mine=(Array.isArray(people)?people:[]).filter(p=>p&&String(p.uid||'')===uid&&normalizeRole(p.role)==='Staff').map(stripPerson);
  const myAtt=uid ? (await pool.query('SELECT payload FROM attendance WHERE uid=$1 ORDER BY created_at ASC',[uid])).rows.map(x=>x.payload) : [];
  return {rcs_people:mine,rcs_users:(Array.isArray(allUsers)?allUsers:[]).filter(u=>u&&String(u.uid||'')===uid).map(safeUser),rcs_greports:[],rcs_att:myAtt};
}

async function syncAuthFromUsers(users){
  const rows=Array.isArray(users)?users:[];
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const keep=new Set();
    for(const raw of rows){
      if(!raw)continue;
      const username=String(raw.username||'').trim().toLowerCase();
      if(!username)continue;
      const role=normalizeRole(raw.role)==='Admin'?'Admin':'Staff';
      const uid=raw.uid?String(raw.uid):null;
      const name=String(raw.name||username);
      const active=raw.active===false?false:true;
      const existing=await client.query('SELECT password_hash FROM auth WHERE username=$1',[username]);
      let hash=existing.rowCount?existing.rows[0].password_hash:null;
      const pw=raw.password!=null?String(raw.password):'';
      if(pw) hash=await bcrypt.hash(pw,12);
      if(!hash) continue;
      await client.query(`INSERT INTO auth(username,password_hash,name,role,uid,active) VALUES($1,$2,$3,$4,$5,$6)
        ON CONFLICT(username) DO UPDATE SET password_hash=EXCLUDED.password_hash,name=EXCLUDED.name,role=EXCLUDED.role,uid=EXCLUDED.uid,active=EXCLUDED.active`,
        [username,hash,name,role,uid,active]);
      keep.add(username);
    }
    const existing=await client.query('SELECT username FROM auth WHERE username<>$1',[ADMIN_USER]);
    for(const row of existing.rows){if(!keep.has(row.username)) await client.query('DELETE FROM auth WHERE username=$1',[row.username]);}
    await client.query('COMMIT');
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}

async function upsertAttendance(rows){
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    for(const r0 of rows||[]){
      if(!r0)continue;
      const r=Object.assign({},r0);
      const id=String(r._eventId||('evt-'+Date.now()+'-'+Math.random().toString(36).slice(2)));
      r._eventId=id;
      await client.query(`INSERT INTO attendance(event_id,uid,payload) VALUES($1,$2,$3::jsonb)
        ON CONFLICT(event_id) DO UPDATE SET uid=EXCLUDED.uid,payload=EXCLUDED.payload`,[id,String(r.uid||''),JSON.stringify(r)]);
    }
    await client.query('COMMIT');
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}

async function init(){
  await pool.query(`CREATE TABLE IF NOT EXISTS snapshots(key TEXT PRIMARY KEY,value JSONB NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS auth(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL,name TEXT NOT NULL,role TEXT NOT NULL,uid TEXT,active BOOLEAN NOT NULL DEFAULT TRUE)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS attendance(event_id TEXT PRIMARY KEY,uid TEXT,payload JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE INDEX IF NOT EXISTS attendance_uid_idx ON attendance(uid)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)`);
  if((await pool.query("SELECT 1 FROM snapshots WHERE key='rcs_people'")).rowCount===0) await saveSnapshot('rcs_people',[]);
  if((await pool.query("SELECT 1 FROM snapshots WHERE key='rcs_users'")).rowCount===0) await saveSnapshot('rcs_users',[{name:'Administrator',username:ADMIN_USER,password:'',role:'Admin',active:true}]);
  if((await pool.query("SELECT 1 FROM snapshots WHERE key='rcs_greports'")).rowCount===0) await saveSnapshot('rcs_greports',[]);
  const hash=await bcrypt.hash(ADMIN_PASS,12);
  await pool.query(`INSERT INTO auth(username,password_hash,name,role,uid,active) VALUES($1,$2,'Administrator','Admin',NULL,TRUE)
    ON CONFLICT(username) DO UPDATE SET password_hash=EXCLUDED.password_hash,name='Administrator',role='Admin',uid=NULL,active=TRUE`,[ADMIN_USER,hash]);
  await syncAuthFromUsers(await getSnapshot('rcs_users',[]));
  await pool.query(`UPDATE auth SET password_hash=$1,name='Administrator',role='Admin',uid=NULL,active=TRUE WHERE username=$2`,[await bcrypt.hash(ADMIN_PASS,12),ADMIN_USER]);
}

const app=express();
app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'20mb'}));
app.get('/api/health',async(req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,service:'ANREM Staff Attendance',database:'postgres',time:new Date().toISOString()})}catch(e){res.status(503).json({ok:false,error:'Database unavailable'})}});
app.post('/api/login',async(req,res)=>{
  try{
    const username=String(req.body.username||'').trim().toLowerCase();
    const password=String(req.body.password||'');
    const q=await pool.query('SELECT username,password_hash,name,role,uid,active FROM auth WHERE username=$1 OR uid=$1 ORDER BY CASE WHEN username=$1 THEN 0 ELSE 1 END LIMIT 1',[username]);
    const row=q.rowCount?q.rows[0]:null;
    if(!row||!(await bcrypt.compare(password,row.password_hash))||!row.active)return res.status(401).json({error:row&&!row.active?'Account paused':'Invalid username or password'});
    const user={username:row.username,name:row.name,role:row.role,uid:row.uid};
    res.json({token:issue(user),user,state:await sanitizeStateFor(user)});
  }catch(e){console.error(e);res.status(500).json({error:'Login failed'})}
});
app.get('/api/state',auth,async(req,res)=>{try{res.json(await sanitizeStateFor(req.user))}catch(e){console.error(e);res.status(500).json({error:'Unable to load state'})}});
app.delete('/api/staff/:uid',auth,adminOnly,async(req,res)=>{
  const uid=String(req.params.uid||'').trim();
  if(!uid)return res.status(400).json({error:'Staff ID required'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const peopleQ=await client.query("SELECT value FROM snapshots WHERE key='rcs_people'");
    const usersQ=await client.query("SELECT value FROM snapshots WHERE key='rcs_users'");
    const people=peopleQ.rowCount&&Array.isArray(peopleQ.rows[0].value)?peopleQ.rows[0].value:[];
    const users=usersQ.rowCount&&Array.isArray(usersQ.rows[0].value)?usersQ.rows[0].value:[];
    const nextPeople=people.filter(p=>p&&String(p.uid||'')!==uid);
    const nextUsers=users.filter(u=>u&&String(u.uid||'')!==uid);
    if(nextPeople.length===people.length && nextUsers.length===users.length){
      await client.query('ROLLBACK');
      return res.status(404).json({error:'Staff record not found'});
    }
    await client.query("INSERT INTO snapshots(key,value) VALUES('rcs_people',$1::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",[JSON.stringify(nextPeople)]);
    await client.query("INSERT INTO snapshots(key,value) VALUES('rcs_users',$1::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",[JSON.stringify(nextUsers)]);
    await client.query('DELETE FROM auth WHERE uid=$1 AND username<>$2',[uid,ADMIN_USER]);
    await client.query('COMMIT');
    res.json({ok:true,state:await sanitizeStateFor(req.user)});
  }catch(e){
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({error:'Unable to delete Staff'});
  }finally{client.release()}
});
app.post('/api/snapshot/:key',auth,adminOnly,async(req,res)=>{
  try{
    const key=req.params.key;
    if(!['rcs_people','rcs_users','rcs_greports'].includes(key))return res.status(400).json({error:'Invalid key'});
    const value=Array.isArray(req.body.value)?req.body.value:[];
    await saveSnapshot(key,value);
    if(key==='rcs_users')await syncAuthFromUsers(value);
    res.json({ok:true,state:await sanitizeStateFor(req.user)});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to save data'})}
});
app.post('/api/attendance/sync',auth,async(req,res)=>{
  try{
    const incoming=Array.isArray(req.body.value)?req.body.value:[];
    const allowed=req.user.role==='Admin'?incoming:incoming.filter(r=>r&&String(r.uid||'')===String(req.user.uid||''));
    await upsertAttendance(allowed);
    res.json({ok:true,state:await sanitizeStateFor(req.user)});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to sync attendance'})}
});
app.put('/api/attendance/:id',auth,adminOnly,async(req,res)=>{
  try{
    const id=String(req.params.id);const q=await pool.query('SELECT payload FROM attendance WHERE event_id=$1',[id]);if(!q.rowCount)return res.status(404).json({error:'Attendance record not found'});
    const next=Object.assign({},q.rows[0].payload,req.body||{},{_eventId:id});
    await pool.query('UPDATE attendance SET uid=$1,payload=$2::jsonb WHERE event_id=$3',[String(next.uid||''),JSON.stringify(next),id]);
    res.json({ok:true,state:await sanitizeStateFor(req.user)});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to edit attendance'})}
});
app.delete('/api/attendance/:id',auth,adminOnly,async(req,res)=>{try{await pool.query('DELETE FROM attendance WHERE event_id=$1',[String(req.params.id)]);res.json({ok:true,state:await sanitizeStateFor(req.user)})}catch(e){console.error(e);res.status(500).json({error:'Unable to delete attendance'})}});
app.post('/api/import',auth,adminOnly,async(req,res)=>{
  try{
    const incoming=req.body||{};
    if(Array.isArray(incoming.rcs_people))await saveSnapshot('rcs_people',incoming.rcs_people);
    if(Array.isArray(incoming.rcs_users)){await saveSnapshot('rcs_users',incoming.rcs_users);await syncAuthFromUsers(incoming.rcs_users)}
    if(Array.isArray(incoming.rcs_greports))await saveSnapshot('rcs_greports',incoming.rcs_greports);
    if(Array.isArray(incoming.rcs_att))await upsertAttendance(incoming.rcs_att);
    res.json({ok:true,state:await sanitizeStateFor(req.user)});
  }catch(e){console.error(e);res.status(500).json({error:'Unable to import backup'})}
});
app.get('/api/export',auth,adminOnly,async(req,res)=>{
  try{
    const users=(await getSnapshot('rcs_users',[])).map(u=>{const x=Object.assign({},u);delete x.password;delete x.loginPassword;delete x.staffPassword;return x});
    const payload={rcs_people:await getSnapshot('rcs_people',[]),rcs_users:users,rcs_greports:await getSnapshot('rcs_greports',[]),rcs_att:await getAllAttendance()};
    res.setHeader('Content-Type','application/json');res.setHeader('Content-Disposition','attachment; filename="anrem-staff-attendance-backup.json"');res.send(JSON.stringify(payload,null,2));
  }catch(e){console.error(e);res.status(500).json({error:'Unable to export backup'})}
});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'..','public','index.html')));

init().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`ANREM Staff Attendance running on port ${PORT}`))).catch(e=>{console.error('Startup failed',e);process.exit(1)});

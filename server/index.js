const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const JWT_SECRET = process.env.JWT_SECRET || 'vibe_secret_key';
const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGO_URL).then(() => console.log('✅ MongoDB connected')).catch(err => console.error('❌ MongoDB error:', err));

const userSchema = new mongoose.Schema({ username:{type:String,unique:true,required:true}, nickname:{type:String,required:true}, password_hash:{type:String,required:true}, avatar_color:{type:String,default:'#4fc3f7'}, bio:{type:String,default:''}, online:{type:Boolean,default:false}, last_seen:{type:Number,default:0}, created_at:{type:Number,default:Date.now} });
const msgSchema = new mongoose.Schema({ id:{type:String,required:true}, conv_key:{type:String,required:true}, from_user:{type:String,required:true}, to_user:{type:String,required:true}, text:{type:String,default:''}, edited:{type:Boolean,default:false}, deleted:{type:Boolean,default:false}, read_at:{type:Number,default:0}, created_at:{type:Number,default:Date.now} });

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', msgSchema);

const convKey = (a,b) => [a,b].sort().join('__');
const COLORS = ['#4fc3f7','#81c784','#ffb74d','#f06292','#ce93d8','#80cbc4','#ff8a65','#90caf9'];
const randomColor = () => COLORS[Math.floor(Math.random()*COLORS.length)];
const clients = new Map();

const sendTo = (u,d) => { const c=clients.get(u); if(!c)return; const p=JSON.stringify(d); for(const w of c) if(w.readyState===WebSocket.OPEN)w.send(p); };
const broadcast = (d) => { const p=JSON.stringify(d); for(const[,c] of clients) for(const w of c) if(w.readyState===WebSocket.OPEN)w.send(p); };

wss.on('connection',(ws)=>{
  let me=null;
  ws.on('message',async(raw)=>{
    let msg; try{msg=JSON.parse(raw);}catch{return;}
    if(msg.type==='auth'){
      try{
        const pl=jwt.verify(msg.token,JWT_SECRET); me=pl.username;
        if(!clients.has(me))clients.set(me,new Set());
        clients.get(me).add(ws);
        await User.updateOne({username:me},{online:true,last_seen:Date.now()});
        broadcast({type:'presence',username:me,online:true});
        ws.send(JSON.stringify({type:'auth_ok'}));
      }catch{ws.send(JSON.stringify({type:'auth_err'}));}
      return;
    }
    if(!me)return;
    if(msg.type==='message'){
      const to=(msg.to||'').toLowerCase(),text=(msg.text||'').trim().slice(0,2000);
      if(!to||!text)return;
      const toUser=await User.findOne({username:to});
      if(!toUser)return;
      const id=uuidv4(),ck=convKey(me,to),ts=Date.now();
      await Message.create({id,conv_key:ck,from_user:me,to_user:to,text,created_at:ts});
      const pkt={type:'message',id,from:me,to,text,ts,edited:false};
      sendTo(me,pkt);sendTo(to,pkt);
    }
    if(msg.type==='read'){
      const ck=convKey(me,msg.partner||'');
      await Message.updateMany({conv_key:ck,to_user:me,read_at:0},{read_at:Date.now()});
      sendTo(msg.partner,{type:'read',by:me});
    }
    if(msg.type==='typing')sendTo(msg.to,{type:'typing',from:me,active:!!msg.active});
    if(msg.type==='edit'){
      const m=await Message.findOne({id:msg.id,from_user:me});
      if(!m)return;
      const newText=(msg.text||'').trim();
      await Message.updateOne({id:msg.id},{text:newText,edited:true});
      sendTo(m.from_user,{type:'edit',id:msg.id,text:newText});
      sendTo(m.to_user,{type:'edit',id:msg.id,text:newText});
    }
    if(msg.type==='delete'){
      const m=await Message.findOne({id:msg.id,from_user:me});
      if(!m)return;
      await Message.updateOne({id:msg.id},{deleted:true,text:''});
      sendTo(m.from_user,{type:'delete',id:msg.id});
      sendTo(m.to_user,{type:'delete',id:msg.id});
    }
  });
  ws.on('close',async()=>{
    if(!me)return;
    const c=clients.get(me);if(c){c.delete(ws);if(c.size===0)clients.delete(me);}
    if(!clients.has(me)){
      await User.updateOne({username:me},{online:false,last_seen:Date.now()});
      broadcast({type:'presence',username:me,online:false,last_seen:Date.now()});
    }
  });
});

app.use(express.json());
app.use(express.static(path.join(__dirname,'../public')));

const verifyToken=(req)=>{const t=(req.headers.authorization||'').replace('Bearer ','');if(!t)return null;try{return jwt.verify(t,JWT_SECRET);}catch{return null;}};

app.post('/api/register',async(req,res)=>{
  const{username,nickname,password}=req.body||{};
  const u=(username||'').toLowerCase().trim();
  if(!/^[a-zA-Z0-9]{4,20}$/.test(u))return res.status(400).json({error:'Username: 4-20 символов, только латиница и цифры'});
  if(!nickname||nickname.length>30)return res.status(400).json({error:'Никнейм: 1-30 символов'});
  if(!password||password.length<4)return res.status(400).json({error:'Пароль минимум 4 символа'});
  if(await User.findOne({username:u}))return res.status(409).json({error:'Username уже занят'});
  const hash=bcrypt.hashSync(password,10);
  const user=await User.create({username:u,nickname,password_hash:hash,avatar_color:randomColor()});
  const token=jwt.sign({username:u},JWT_SECRET,{expiresIn:'30d'});
  const{password_hash,...safe}=user.toObject();
  res.json({token,user:safe});
});

app.post('/api/login',async(req,res)=>{
  const{username,password}=req.body||{};
  const u=(username||'').toLowerCase().trim();
  const user=await User.findOne({username:u});
  if(!user||!bcrypt.compareSync(password,user.password_hash))return res.status(401).json({error:'Неверный username или пароль'});
  const token=jwt.sign({username:u},JWT_SECRET,{expiresIn:'30d'});
  const{password_hash,...safe}=user.toObject();
  res.json({token,user:safe});
});

app.get('/api/me',async(req,res)=>{
  const p=verifyToken(req);if(!p)return res.status(401).json({error:'Unauthorized'});
  const user=await User.findOne({username:p.username});if(!user)return res.status(404).json({error:'Not found'});
  const{password_hash,...safe}=user.toObject();res.json(safe);
});

app.patch('/api/me',async(req,res)=>{
  const p=verifyToken(req);if(!p)return res.status(401).json({error:'Unauthorized'});
  const{nickname,bio,avatar_color,old_password,new_password}=req.body||{};
  const user=await User.findOne({username:p.username});if(!user)return res.status(404).json({error:'Not found'});
  if(nickname)user.nickname=nickname.trim().slice(0,30);
  if(bio!==undefined)user.bio=bio.slice(0,150);
  if(avatar_color)user.avatar_color=avatar_color;
  if(old_password&&new_password){
    if(!bcrypt.compareSync(old_password,user.password_hash))return res.status(400).json({error:'Старый пароль неверный'});
    if(new_password.length<4)return res.status(400).json({error:'Новый пароль минимум 4 символа'});
    user.password_hash=bcrypt.hashSync(new_password,10);
  }
  await user.save();
  const{password_hash,...safe}=user.toObject();res.json(safe);
});

app.get('/api/users/search',async(req,res)=>{
  const p=verifyToken(req);if(!p)return res.status(401).json({error:'Unauthorized'});
  const q=(req.query.q||'').toLowerCase().trim();if(!q)return res.json([]);
  const users=await User.find({username:{$regex:'^'+q},_id:{$ne:(await User.findOne({username:p.username}))?._id}}).limit(10);
  res.json(users.map(u=>{const{password_hash,...s}=u.toObject();return s;}));
});

app.get('/api/users/:username',async(req,res)=>{
  const p=verifyToken(req);if(!p)return res.status(401).json({error:'Unauthorized'});
  const user=await User.findOne({username:req.params.username.toLowerCase()});
  if(!user)return res.status(404).json({error:'Не найден'});
  const{password_hash,...safe}=user.toObject();res.json(safe);
});

app.get('/api/messages/:partner',async(req,res)=>{
  const p=verifyToken(req);if(!p)return res.status(401).json({error:'Unauthorized'});
  const ck=convKey(p.username,req.params.partner.toLowerCase());
  const msgs=await Message.find({conv_key:ck}).sort({created_at:1}).limit(50);
  res.json(msgs.map(m=>({...m.toObject(),ts:m.created_at})));
});

app.get('/api/conversations',async(req,res)=>{
  const p=verifyToken(req);if(!p)return res.status(401).json({error:'Unauthorized'});
  const lastMsgs=await Message.aggregate([
    {$match:{$or:[{from_user:p.username},{to_user:p.username}]}},
    {$sort:{created_at:-1}},
    {$group:{_id:'$conv_key',doc:{$first:'$$ROOT'}}},
    {$replaceRoot:{newRoot:'$doc'}}
  ]);
  const result=await Promise.all(lastMsgs.map(async m=>{
    const other=m.from_user===p.username?m.to_user:m.from_user;
    const partner=await User.findOne({username:other});
    if(!partner)return null;
    const unread=await Message.countDocuments({conv_key:m.conv_key,to_user:p.username,read_at:0});
    const{password_hash,...ps}=partner.toObject();
    return{conv_key:m.conv_key,from_user:m.from_user,to_user:m.to_user,text:m.text,deleted:m.deleted,created_at:m.created_at,unread,partner:ps};
  }));
  res.json(result.filter(Boolean).sort((a,b)=>b.created_at-a.created_at));
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'../public/index.html')));
server.listen(PORT,()=>console.log(`✅ Vibe запущен на http://localhost:${PORT}`));

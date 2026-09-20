const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const admin = require('firebase-admin');

function json(res,status,body){
  res.status(status).setHeader('Content-Type','application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function env(name, fallback=''){
  return process.env[name] || fallback;
}

function initFirebase(){
  if(admin.apps.length) return admin.app();
  let service;
  if(process.env.FIREBASE_SERVICE_ACCOUNT_JSON){
    service=JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  }else if(process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY){
    service={
      projectId:process.env.FIREBASE_PROJECT_ID,
      clientEmail:process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g,'\n')
    };
  }else{
    throw new Error('Firebase Admin credentials are not configured.');
  }
  return admin.initializeApp({credential:admin.credential.cert(service),databaseURL:env('FIREBASE_DATABASE_URL')});
}

function s3(){
  const endpoint=env('B2_ENDPOINT');
  const region=env('B2_REGION','us-east-005');
  const bucket=env('B2_BUCKET');
  const keyId=env('B2_KEY_ID');
  const applicationKey=env('B2_APPLICATION_KEY');
  if(!endpoint||!bucket||!keyId||!applicationKey) throw new Error('Backblaze B2 environment variables are not configured.');
  return {
    client:new S3Client({region,endpoint,forcePathStyle:false,credentials:{accessKeyId:keyId,secretAccessKey:applicationKey}}),
    bucket
  };
}

function cleanPart(value,max=120){
  return String(value||'').trim().replace(/[^a-zA-Z0-9._-]/g,'-').replace(/-+/g,'-').slice(0,max);
}

function safeStorageKey({dept,topic,id,name}){
  const d=cleanPart(dept,40), t=cleanPart(topic,40), i=cleanPart(id,100);
  const original=cleanPart(name,180) || 'file';
  const stamp=Date.now();
  return `lms/${d}/${t}/${i}/${stamp}-${original}`;
}

async function requireAuth(req,requiredRole){
  const header=String(req.headers.authorization||'');
  if(!header.startsWith('Bearer ')) throw Object.assign(new Error('Authentication required.'),{status:401});
  const token=header.slice(7).trim();
  if(!token) throw Object.assign(new Error('Authentication required.'),{status:401});
  const app=initFirebase();
  const decoded=await admin.auth(app).verifyIdToken(token);
  if(requiredRole){
    const username=String(decoded.email||'').split('@')[0];
    if(!username) throw Object.assign(new Error('Could not determine LMS user.'),{status:403});
    const snap=await admin.database(app).ref(`users/${username}/role`).once('value');
    const role=String(snap.val()||'');
    if(!(role==='admin'||role==='content')) throw Object.assign(new Error('Admin/content permissions required.'),{status:403});
  }
  return decoded;
}

function assertStorageKey(key){
  if(!key || typeof key!=='string' || !key.startsWith('lms/') || key.includes('..') || key.includes('\\')){
    throw Object.assign(new Error('Invalid storage key.'),{status:400});
  }
}

module.exports=async function handler(req,res){
  try{
    const action=String(req.query.action||'');
    if(req.method==='OPTIONS') return res.status(204).end();

    if(action==='prepareUpload'){
      await requireAuth(req,true);
      if(req.method!=='GET') return json(res,405,{error:'Method not allowed.'});
      const name=String(req.query.name||'file');
      const type=String(req.query.type||'application/octet-stream');
      const dept=String(req.query.dept||'');
      const topic=String(req.query.topic||'');
      const id=String(req.query.id||'');
      if(!dept||!topic||!id) return json(res,400,{error:'dept, topic and id are required.'});
      if(!['video/','image/'].some(x=>type.startsWith(x)) && type!=='application/pdf'){
        return json(res,400,{error:'Only video, image and PDF uploads are allowed.'});
      }
      const {client,bucket}=s3();
      const key=safeStorageKey({dept,topic,id,name});
      const command=new PutObjectCommand({Bucket:bucket,Key:key,ContentType:type,Metadata:{originalname:name.slice(0,500)}});
      const uploadUrl=await getSignedUrl(client,command,{expiresIn:Number(env('B2_SIGNED_URL_TTL','900'))});
      return json(res,200,{ok:true,uploadUrl,storageKey:key,expiresIn:Number(env('B2_SIGNED_URL_TTL','900'))});
    }

    if(action==='download'){
      await requireAuth(req,false);
      if(req.method!=='GET') return json(res,405,{error:'Method not allowed.'});
      const key=String(req.query.key||'');
      assertStorageKey(key);
      const {client,bucket}=s3();
      const command=new GetObjectCommand({Bucket:bucket,Key:key});
      const url=await getSignedUrl(client,command,{expiresIn:Number(env('B2_DOWNLOAD_TTL','900'))});
      return json(res,200,{ok:true,url,expiresIn:Number(env('B2_DOWNLOAD_TTL','900'))});
    }

    return json(res,400,{error:'Unknown action.'});
  }catch(err){
    console.error('B2 API error',err);
    const status=Number(err.status)||500;
    return json(res,status,{error:status===500?'Server configuration or storage error.':(err.message||'Request failed.')});
  }
};

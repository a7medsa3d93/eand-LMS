import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const projectId = process.env.FIREBASE_PROJECT_ID || 'lms-demo-e0348';
const databaseUrl = process.env.FIREBASE_DATABASE_URL || 'https://lms-demo-e0348-default-rtdb.firebaseio.com';
const bucket = process.env.B2_BUCKET || 'eandadvocate';
const endpoint = process.env.B2_ENDPOINT || 'https://s3.us-east-005.backblazeb2.com';
const s3 = new S3Client({ region: 'us-east-005', endpoint, credentials: { accessKeyId: process.env.B2_KEY_ID, secretAccessKey: process.env.B2_APPLICATION_KEY } });
const jwks = createRemoteJWKSet(new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'));

async function authUser(req){
  const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) throw new Error('Authentication required');
  const token=h.slice(7);
  const {payload}=await jwtVerify(token,jwks,{issuer:`https://securetoken.google.com/${projectId}`,audience:projectId});
  if(!payload.sub)throw new Error('Invalid token');
  const username=String(payload.email||'').split('@')[0];
  if(!username)throw new Error('Invalid LMS account');
  const r=await fetch(`${databaseUrl}/users/${encodeURIComponent(username)}.json?auth=${encodeURIComponent(token)}`);
  if(!r.ok)throw new Error('Could not verify LMS profile');
  const user=await r.json(); if(!user)throw new Error('LMS profile not found');
  return {username,user};
}

function cleanName(name){return String(name||'file').replace(/[^a-zA-Z0-9._-]/g,'_').slice(-120);}
function json(res,status,data){res.status(status).setHeader('Content-Type','application/json');res.end(JSON.stringify(data));}

export default async function handler(req,res){
  try{
    const {username,user}=await authUser(req);
    const action=req.query.action;
    if(action==='upload'){
      if(!['admin','content'].includes(user.role))return json(res,403,{error:'Admin/Content access required'});
      const dept=String(req.query.dept||''); const topic=String(req.query.topic||''); const id=String(req.query.id||'');
      if(!['corporate','consumer','technical','non-telecom'].includes(dept)||!['rateplan','service','process','tnps'].includes(topic)||!id)return json(res,400,{error:'Invalid content path'});
      const name=cleanName(req.query.name); const contentType=String(req.query.type||'application/octet-stream');
      if(!contentType.startsWith('video/') && contentType!=='application/pdf')return json(res,400,{error:'Only video and PDF uploads are supported'});
      const storageKey=`content/${dept}/${topic}/${id}/${Date.now()}-${name}`;
      const command=new PutObjectCommand({Bucket:bucket,Key:storageKey});
      const uploadUrl=await getSignedUrl(s3,command,{expiresIn:600});
      return json(res,200,{uploadUrl,storageKey,uploadHeaders:{'Content-Type':contentType}});
    }
    if(action==='download'){
      const key=String(req.query.key||'');
      const prefix=`content/${user.department||''}/`;
      if(!key.startsWith(prefix))return json(res,403,{error:'Content access denied'});
      const command=new GetObjectCommand({Bucket:bucket,Key:key});
      const url=await getSignedUrl(s3,command,{expiresIn:900});
      return json(res,200,{url});
    }
    return json(res,400,{error:'Unknown action'});
  }catch(e){console.error(e);return json(res,401,{error:e.message||'Unauthorized'});}
}

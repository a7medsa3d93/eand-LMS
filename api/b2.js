import { createRemoteJWKSet, jwtVerify } from 'jose';

const projectId = process.env.FIREBASE_PROJECT_ID || 'lms-demo-e0348';
const databaseUrl = process.env.FIREBASE_DATABASE_URL || 'https://lms-demo-e0348-default-rtdb.firebaseio.com';
const bucket = process.env.B2_BUCKET || 'eandadvocate';
const bucketId = process.env.B2_BUCKET_ID || '2cb9b63849f87ac5aa0f041d';
const keyId = process.env.B2_KEY_ID || '';
const applicationKey = process.env.B2_APPLICATION_KEY || '';
const jwks = createRemoteJWKSet(new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'));

let b2AuthCache = null;

async function authUser(req){
  const h=req.headers.authorization||'';
  if(!h.startsWith('Bearer ')) throw new Error('Authentication required');
  const token=h.slice(7);
  const {payload}=await jwtVerify(token,jwks,{issuer:`https://securetoken.google.com/${projectId}`,audience:projectId});
  if(!payload.sub)throw new Error('Invalid token');
  const username=String(payload.email||'').split('@')[0];
  if(!username)throw new Error('Invalid LMS account');
  const r=await fetch(`${databaseUrl}/users/${encodeURIComponent(username)}.json?auth=${encodeURIComponent(token)}`);
  if(!r.ok)throw new Error('Could not verify LMS profile');
  const user=await r.json();
  if(!user)throw new Error('LMS profile not found');
  return {username,user};
}

function cleanName(name){return String(name||'file').replace(/[^a-zA-Z0-9._-]/g,'_').slice(-120);}
function json(res,status,data){res.status(status).setHeader('Content-Type','application/json');res.end(JSON.stringify(data));}

async function b2Authorize(){
  if(!keyId||!applicationKey)throw new Error('Backblaze credentials are not configured on Vercel.');
  if(b2AuthCache && b2AuthCache.expiresAt>Date.now()+60000)return b2AuthCache;
  const basic=Buffer.from(`${keyId}:${applicationKey}`).toString('base64');
  const r=await fetch('https://api.backblazeb2.com/b2api/v4/b2_authorize_account',{headers:{Authorization:`Basic ${basic}`}});
  const text=await r.text();
  let d={};try{d=text?JSON.parse(text):{};}catch{d={};}
  if(!r.ok)throw new Error(d.message||d.code||`Backblaze authorization failed (${r.status})`);
  const apiUrl=d?.apiInfo?.storageApi?.apiUrl;
  if(!apiUrl) throw new Error('Backblaze authorization response did not include apiInfo.storageApi.apiUrl.');
  b2AuthCache={apiUrl,authorizationToken:d.authorizationToken,expiresAt:Date.now()+23*60*60*1000};
  return b2AuthCache;
}

async function b2GetUploadUrl(){
  let auth=await b2Authorize();
  let r=await fetch(`${auth.apiUrl}/b2api/v4/b2_get_upload_url?bucketId=${encodeURIComponent(bucketId)}`,{headers:{Authorization:auth.authorizationToken}});
  let text=await r.text();let d={};try{d=text?JSON.parse(text):{};}catch{}
  if(!r.ok){
    b2AuthCache=null;
    auth=await b2Authorize();
    r=await fetch(`${auth.apiUrl}/b2api/v4/b2_get_upload_url?bucketId=${encodeURIComponent(bucketId)}`,{headers:{Authorization:auth.authorizationToken}});
    text=await r.text();d={};try{d=text?JSON.parse(text):{};}catch{}
  }
  if(!r.ok)throw new Error(d.message||d.code||`Could not get Backblaze upload URL (${r.status})`);
  return d;
}

export default async function handler(req,res){
  try{
    const {user}=await authUser(req);
    const action=req.query.action;
    if(action==='upload'){
      if(!['admin','content'].includes(user.role))return json(res,403,{error:'Admin/Content access required'});
      const dept=String(req.query.dept||'');
      const topic=String(req.query.topic||'');
      const id=String(req.query.id||'');
      if(!['corporate','consumer','technical','non-telecom'].includes(dept)||!['rateplan','service','process','tnps'].includes(topic)||!id)return json(res,400,{error:'Invalid content path'});
      const name=cleanName(req.query.name);
      const contentType=String(req.query.type||'application/octet-stream');
      if(!contentType.startsWith('video/') && !contentType.startsWith('image/') && contentType!=='application/pdf')return json(res,400,{error:'Only video, image, and PDF uploads are supported'});
      const storageKey=`content/${dept}/${topic}/${id}/${Date.now()}-${name}`;
      const upload=await b2GetUploadUrl();
      return json(res,200,{uploadUrl:upload.uploadUrl,authorizationToken:upload.authorizationToken,storageKey,bucket});
    }
    if(action==='download'){
      const key=String(req.query.key||'');
      const prefix=`content/${user.department||''}/`;
      if(!key.startsWith(prefix))return json(res,403,{error:'Content access denied'});
      // Downloads stay on the existing private S3 path for now; upload flow is Native API.
      const { S3Client, GetObjectCommand } = await import('@aws-sdk/client-s3');
      const { getSignedUrl } = await import('@aws-sdk/s3-request-presigner');
      const s3=new S3Client({region:'us-east-005',endpoint:process.env.B2_ENDPOINT||'https://s3.us-east-005.backblazeb2.com',credentials:{accessKeyId:keyId,secretAccessKey:applicationKey}});
      const command=new GetObjectCommand({Bucket:bucket,Key:key});
      const url=await getSignedUrl(s3,command,{expiresIn:900});
      return json(res,200,{url});
    }
    return json(res,400,{error:'Unknown action'});
  }catch(e){console.error(e);return json(res,401,{error:e.message||'Unauthorized'});}
}

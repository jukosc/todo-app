"""Trusted image-only deployment actor. Fixed namespaced APIs; no shell/exec/Pod reads."""
import argparse,base64,copy,hashlib,ipaddress,json,os,re,signal,socket,ssl,time
from http.client import IncompleteRead
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,ProxyHandler,HTTPSHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError
class SafeError(Exception):
 def __init__(self,code,**details):super().__init__(code);self.details=details
def fail(code,**details):raise SafeError(code,**details)
def transport_kind(error):
 reason=error.reason if isinstance(error,URLError) else error
 if isinstance(reason,ssl.SSLCertVerificationError):return 'TLS_VERIFY'
 if isinstance(reason,ssl.SSLError):return 'TLS'
 if isinstance(reason,(TimeoutError,socket.timeout)):return 'TIMEOUT'
 if isinstance(reason,ConnectionResetError):return 'CONNECTION_RESET'
 if isinstance(reason,ConnectionRefusedError):return 'CONNECTION_REFUSED'
 if isinstance(reason,IncompleteRead):return 'INCOMPLETE_READ'
 return 'NETWORK'
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):fail('REDIRECT_DENIED')
def validate_binding(b):
 required={'namespace','deployment','service','deployment_uid','service_uid','cluster_owner','cluster_participant','profile_id','resource_prefix','fixture','service_selector','app_template'}
 if not isinstance(b,dict) or set(b)!=required:fail('BINDING_KEYS_INVALID')
 for name in ('namespace','deployment','service','resource_prefix'):
  if not isinstance(b[name],str) or not re.fullmatch('[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?',b[name]):fail('BINDING_NAME_INVALID')
 if b['deployment']!=b['resource_prefix']+'-todo-app' or b['service']!=b['deployment']:fail('PARTICIPANT_TARGET_MISMATCH')
 for name in ('deployment_uid','service_uid'):
  if not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',b[name]):fail('BINDING_UID_INVALID')
 if not re.fullmatch('[a-f0-9]{32}',b['cluster_owner']) or not re.fullmatch('d3-[a-f0-9]{8}',b['cluster_participant']) or not re.fullmatch('[a-f0-9]{32}',b['profile_id']):fail('BINDING_OWNER_INVALID')
 if b['service_selector']!={'app.kubernetes.io/name':b['deployment'],'training.day3.owner':b['cluster_owner']} or not isinstance(b['app_template'],dict):fail('BINDING_SELECTOR_INVALID')
 f=b['fixture']
 if not isinstance(f,dict) or set(f)!={'id','title','completed'} or type(f['id']) is not int or f['id']<1 or type(f['completed']) is not bool or f['title']!='d3-persistent-'+b['cluster_participant']:fail('BINDING_FIXTURE_INVALID')
 return b
def template_matches(actual,expected,path=''):
 defaults={'/metadata':{'creationTimestamp':None},'/spec':{'restartPolicy':'Always','terminationGracePeriodSeconds':30,'dnsPolicy':'ClusterFirst','schedulerName':'default-scheduler','serviceAccountName':'','serviceAccount':''},'/spec/containers/*':{'terminationMessagePath':'/dev/termination-log','terminationMessagePolicy':'File'},'/spec/containers/*/ports/*':{'protocol':'TCP'}}
 if path.endswith(('startupProbe','livenessProbe','readinessProbe')):defaults[path]={'initialDelaySeconds':0,'timeoutSeconds':1,'periodSeconds':10,'successThreshold':1,'failureThreshold':3}
 if path.endswith('/httpGet'):defaults[path]={'scheme':'HTTP'}
 if isinstance(expected,dict):
  if not isinstance(actual,dict):return False
  if any(k not in expected and (k not in defaults.get(path,{}) or v!=defaults[path][k]) for k,v in actual.items()):return False
  return all(k in actual and template_matches(actual[k],v,path+'/'+k) for k,v in expected.items())
 if isinstance(expected,list):return isinstance(actual,list) and len(actual)==len(expected) and all(template_matches(a,b,path+'/*') for a,b in zip(actual,expected))
 return actual==expected

def initial_template_guard(live,binding):
 actual=copy.deepcopy(live['spec']['template']);expected=copy.deepcopy(binding['app_template'])
 actual['spec']['containers'][0]['image']=expected['spec']['containers'][0]['image']
 if not template_matches(actual,expected):fail('HANDOFF_TEMPLATE_DRIFT')

class API:
 def __init__(self,path,binding):
  self.b=validate_binding(binding);p=Path(path)
  if p.is_symlink() or not p.is_file() or p.stat().st_nlink!=1 or p.stat().st_size>131072:fail('CI_CONFIG_UNSAFE')
  if os.name!='nt' and p.stat().st_mode&0o077:fail('CI_CONFIG_NOT_PRIVATE')
  before=p.stat();fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  with os.fdopen(fd,'rb') as f:
   opened=os.fstat(f.fileno())
   if (before.st_dev,before.st_ino,before.st_size)!=(opened.st_dev,opened.st_ino,opened.st_size):fail('CI_CONFIG_CHANGED')
   c=json.loads(f.read(131073))
  if set(c)!={'apiVersion','kind','clusters','contexts','current-context','users'} or c['apiVersion']!='v1' or c['kind']!='Config' or len(c['clusters'])!=1 or len(c['contexts'])!=1 or len(c['users'])!=1 or c['current-context']!='training-ci':fail('CI_CONFIG_SHAPE_INVALID')
  cl=c['clusters'][0];ct=c['contexts'][0];user=c['users'][0]
  if cl['name']!='training-ci' or ct['name']!='training-ci' or user['name']!='training-ci' or ct['context']!={'cluster':'training-ci','user':'training-ci','namespace':self.b['namespace']} or set(cl['cluster'])!={'server','certificate-authority-data'} or set(user['user'])!={'token'}:fail('CI_CONFIG_FIELDS_INVALID')
  self.server=cl['cluster']['server'];u=urlsplit(self.server)
  if u.scheme!='https' or u.username or u.password or u.query or u.fragment or u.path not in ('','/') or not u.hostname:fail('CI_SERVER_INVALID')
  try:
   if not ipaddress.ip_address(u.hostname).is_global:fail('CI_SERVER_NOT_PUBLIC')
  except ValueError:fail('CI_SERVER_LITERAL_IP_REQUIRED')
  self.token=user['user']['token']
  if not isinstance(self.token,str) or len(self.token)>32768 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',self.token):fail('CI_TOKEN_INVALID')
  ca=base64.b64decode(cl['cluster']['certificate-authority-data'],validate=True).decode('ascii')
  self.opener=build_opener(ProxyHandler({}),NoRedirect(),HTTPSHandler(context=ssl.create_default_context(cadata=ca)))
 def request(self,path,method='GET',body=None,accepted=(200,),content_type='application/json'):
  ns='/api/v1/namespaces/'+self.b['namespace'];dep='/apis/apps/v1/namespaces/'+self.b['namespace']+'/deployments/'+self.b['deployment'];svc=ns+'/services/'+self.b['service'];proxy=ns+'/services/http:'+self.b['service']+':80/proxy'
  paths={dep:{'GET','PATCH'},svc:{'GET'},'/apis/authentication.k8s.io/v1/selfsubjectreviews':{'POST'},'/apis/authorization.k8s.io/v1/selfsubjectaccessreviews':{'POST'}}
  if path.startswith(proxy):
   tail=path[len(proxy):]
   if not re.fullmatch(r'/(healthz|readyz|version|api/todos(?:/[1-9][0-9]*)?)',tail) or method not in ('GET','POST','PATCH','DELETE'):fail('PROXY_PATH_DENIED')
  elif path not in paths or method not in paths[path]:fail('API_PATH_DENIED')
  if path==dep:operation='deployment_'+method
  elif path==svc:operation='service_'+method
  elif path.endswith('/selfsubjectreviews'):operation='identity_'+method
  elif path.endswith('/selfsubjectaccessreviews'):operation='permission_'+method
  else:
   route={'/healthz':'health','/readyz':'ready','/version':'version','/api/todos':'todos'}.get(path[len(proxy):],'todo')
   operation='proxy_'+route+'_'+method
  req=Request(self.server.rstrip('/')+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Bearer '+self.token,'Content-Type':content_type,'Accept':'application/json'})
  attempts=3 if method=='GET' else 1
  for attempt in range(1,attempts+1):
   try:
    with self.opener.open(req,timeout=15) as r:status=r.status;raw=r.read(65537)
   except HTTPError as e:
    fail('CI_API_STATUS_OR_SIZE_FAILED',operation=operation,attempt=attempt,http_status=e.code)
   except SafeError:raise
   except Exception as e:
    kind=transport_kind(e)
    if method=='GET' and kind not in ('TLS_VERIFY','TLS') and attempt<attempts:
     time.sleep(attempt);continue
    fail('CI_API_TRANSPORT_FAILED',operation=operation,transport=kind,attempt=attempt)
   break
  if len(raw)>65536 or status not in accepted:fail('CI_API_STATUS_OR_SIZE_FAILED',operation=operation,attempt=attempt,http_status=status)
  try:data=json.loads(raw)
  except Exception:fail('CI_API_JSON_FAILED',operation=operation,attempt=attempt,http_status=status)
  return data
 def deployment(self):return self.request('/apis/apps/v1/namespaces/'+self.b['namespace']+'/deployments/'+self.b['deployment'])
 def guard(self,obj,kind='Deployment'):
  m=obj.get('metadata',{});expected=self.b['deployment_uid' if kind=='Deployment' else 'service_uid'];name=self.b['deployment' if kind=='Deployment' else 'service']
  if obj.get('kind')!=kind or m.get('uid')!=expected or m.get('name')!=name or m.get('namespace')!=self.b['namespace'] or m.get('labels',{}).get('training.day3.owner')!=self.b['cluster_owner'] or m.get('labels',{}).get('training.day3.participant')!=self.b['cluster_participant'] or not re.fullmatch('[0-9]+',m.get('resourceVersion','')):fail('LIVE_TARGET_OWNERSHIP_FAILED')
  if kind=='Deployment':
   containers=obj['spec']['template']['spec']['containers']
   if len(containers)!=1 or containers[0]['name']!='app' or obj['spec'].get('replicas')!=1:fail('LIVE_DEPLOYMENT_SHAPE_FAILED')
   if not any(x.get('name')=='http' and x.get('containerPort')==8080 for x in containers[0].get('ports',[])):fail('LIVE_APP_PORT_CHANGED')
  else:
   spec=obj.get('spec',{});ports=spec.get('ports',[])
   if spec.get('type')!='ClusterIP' or spec.get('externalName') or spec.get('selector')!=self.b['service_selector'] or len(ports)!=1 or any(ports[0].get(k)!=v for k,v in {'name':'http','port':80,'targetPort':'http','protocol':'TCP'}.items()):fail('LIVE_SERVICE_MAPPING_FAILED')
  return obj
 def proxy(self,path,method='GET',body=None,accepted=(200,)):
  return self.request('/api/v1/namespaces/'+self.b['namespace']+'/services/http:'+self.b['service']+':80/proxy'+path,method,body,accepted)
 def smoke(self,version=None):
  self.guard(self.request('/api/v1/namespaces/'+self.b['namespace']+'/services/'+self.b['service']),'Service')
  health=self.proxy('/healthz');ready=self.proxy('/readyz');v=self.proxy('/version');rows=self.proxy('/api/todos')
  if not isinstance(v.get('version'),str) or not re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:-day5\.[a-z0-9]{1,32})?',v['version']):fail('RELEASE_VERSION_INVALID')
  if health.get('status')!='healthy' or ready.get('status')!='ready' or ready.get('storage')!='postgres' or (version is not None and v.get('version')!=version):fail('RELEASE_HTTP_FAILED')
  f=self.b['fixture']
  if not isinstance(rows,list) or not any(all(x.get(k)==value for k,value in f.items()) for x in rows if isinstance(x,dict)):fail('PERSISTENT_FIXTURE_FAILED')
  return {'healthy':True,'ready_postgres':True,'version':v.get('version'),'fixture_preserved':True}
 def crud(self,release):
  title='ci-'+hashlib.sha256(release.encode()).hexdigest()[:24];rows=self.proxy('/api/todos')
  if any(x.get('title')==title for x in rows):fail('TRANSIENT_FIXTURE_COLLISION')
  row=self.proxy('/api/todos','POST',{'title':title},accepted=(201,));ident=row.get('id')
  if type(ident) is not int or ident<1 or row.get('title')!=title:fail('TRANSIENT_CREATE_FAILED')
  try:
   updated=self.proxy('/api/todos/'+str(ident),'PATCH',{'completed':True})
   if updated.get('id')!=ident or updated.get('title')!=title or updated.get('completed') is not True:fail('TRANSIENT_UPDATE_FAILED')
  finally:
   # Recheck the transient title before deleting this exact record. Never delete inherited fixture.
   current=next((x for x in self.proxy('/api/todos') if x.get('id')==ident),None)
   if current is None or current.get('title')!=title:fail('TRANSIENT_OWNERSHIP_CHANGED')
   self.proxy('/api/todos/'+str(ident),'DELETE')
  if any(x.get('id')==ident for x in self.proxy('/api/todos')):fail('TRANSIENT_DELETE_FAILED')
  return {'transient_CRUD_verified':True,'transient_id_deleted':ident}
 def patch_image(self,live,new):
  self.guard(live);m=live['metadata'];old=live['spec']['template']['spec']['containers'][0]['image'];ops=[{'op':'test','path':p,'value':v} for p,v in [('/metadata/uid',m['uid']),('/metadata/resourceVersion',m['resourceVersion']),('/metadata/labels/training.day3.owner',self.b['cluster_owner']),('/metadata/labels/training.day3.participant',self.b['cluster_participant']),('/spec/template/spec/containers/0/name','app'),('/spec/template/spec/containers/0/image',old)]]
  ops.append({'op':'replace','path':'/spec/template/spec/containers/0/image','value':new})
  # Dot label keys need no JSON-pointer escaping; only slash and tilde would.
  result=self.request('/apis/apps/v1/namespaces/'+self.b['namespace']+'/deployments/'+self.b['deployment'],'PATCH',ops,content_type='application/json-patch+json');self.guard(result);return result
 def wait_ready(self,image,template,budget=180):
  deadline=time.monotonic()+budget
  while time.monotonic()<deadline:
   live=self.guard(self.deployment());actual=live['spec']['template']
   if actual!=template or actual['spec']['containers'][0]['image']!=image:fail('CONCURRENT_TEMPLATE_CHANGE')
   status=live.get('status',{})
   if status.get('observedGeneration',0)>=live['metadata']['generation'] and all(status.get(k,0)==1 for k in ('replicas','updatedReplicas','availableReplicas','readyReplicas')):return live
   time.sleep(2)
  fail('ROLLOUT_TIMEOUT')
def preflight_permissions(b):
 prefix=b['resource_prefix']
 return [
 ({'group':'apps','resource':'deployments','name':b['deployment'],'verb':'patch'},True),
 ({'group':'apps','resource':'deployments','name':prefix+'-other-app','verb':'patch'},False),
 ({'resource':'secrets','verb':'get'},False),({'resource':'pods','verb':'create'},False),
 ({'resource':'services','subresource':'proxy','name':'http:'+b['service']+':80','verb':'get'},True),
 ({'group':'apps','resource':'statefulsets','name':prefix+'-todo-db','verb':'patch'},False),
 ({'resource':'persistentvolumeclaims','name':prefix+'-postgres-data-'+prefix+'-todo-db-0','verb':'patch'},False),
 ({'resource':'persistentvolumeclaims','name':prefix+'-postgres-data-'+prefix+'-todo-db-0','verb':'delete'},False),
 ({'resource':'pods','verb':'list'},False),
 ({'resource':'pods','subresource':'exec','name':prefix+'-todo-db-0','verb':'create'},False),
 ({'resource':'namespaces','verb':'create'},False),
 ({'resource':'services','subresource':'proxy','name':'http:'+prefix+'-other-app:80','verb':'get'},False)]

def hosted_preflight(api,version):
 match=re.fullmatch(r'1\.0\.1-day5\.(s[0-9]{8}|[a-f0-9]{8})',version)
 if not match:fail('PREFLIGHT_VERSION_INVALID')
 suffix=match[1];suffix=suffix[1:] if suffix.startswith('s') else suffix
 name=api.b['resource_prefix']+'-ci-'+suffix;subject='system:serviceaccount:'+api.b['namespace']+':'+name
 try:
  part=api.token.split('.')[1];claims=json.loads(base64.urlsafe_b64decode(part+'='*((-len(part))%4)))
  uid=claims['kubernetes.io']['serviceaccount']['uid']
  valid=claims['sub']==subject and claims['kubernetes.io']['namespace']==api.b['namespace'] and claims['kubernetes.io']['serviceaccount']['name']==name and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',uid) and type(claims['exp']) is int and claims['exp']>=int(time.time())+900 and isinstance(claims['aud'],list) and 1<=len(claims['aud'])<=8 and all(isinstance(x,str) and 1<=len(x)<=512 for x in claims['aud'])
 except Exception:fail('PREFLIGHT_TOKEN_BINDING_INVALID')
 if not valid:fail('PREFLIGHT_TOKEN_BINDING_INVALID')
 who=api.request('/apis/authentication.k8s.io/v1/selfsubjectreviews','POST',{'apiVersion':'authentication.k8s.io/v1','kind':'SelfSubjectReview'},accepted=(200,201))
 if who.get('status',{}).get('userInfo',{}).get('username')!=subject or who.get('status',{}).get('userInfo',{}).get('uid')!=uid:fail('PREFLIGHT_AUTH_IDENTITY_INVALID')
 for attr,allowed in preflight_permissions(api.b):
  attrs=dict(attr)
  if attrs['resource']!='namespaces':attrs['namespace']=api.b['namespace']
  reply=api.request('/apis/authorization.k8s.io/v1/selfsubjectaccessreviews','POST',{'apiVersion':'authorization.k8s.io/v1','kind':'SelfSubjectAccessReview','spec':{'resourceAttributes':attrs}},accepted=(200,201))
  status=reply.get('status',{})
  if status.get('evaluationError') or type(status.get('allowed')) is not bool or status['allowed']!=allowed:fail('PREFLIGHT_EFFECTIVE_PERMISSION_FAILED')
 live=api.guard(api.deployment());initial_template_guard(live,api.b)
 if live['spec']['template']['spec']['containers'][0]['image']!=api.b['app_template']['spec']['containers'][0]['image']:fail('PREFLIGHT_BASELINE_IMAGE_CHANGED')
 status=live.get('status',{})
 if status.get('observedGeneration',0)<live['metadata']['generation'] or any(status.get(k)!=1 for k in ('replicas','updatedReplicas','availableReplicas','readyReplicas')):fail('PREFLIGHT_BASELINE_NOT_READY')
 proof=api.smoke()
 return {'hosted_preflight_verified':True,'runner_environment':'github-hosted','CI_identity_verified':True,'CI_UID_verified':True,'permission_checks_verified':12,'baseline_image_verified':True,'baseline_ready':True,'fixture_preserved':proof['fixture_preserved'],'baseline_version':proof['version'],'workload_mutated':False,'credential_output':False}

def deploy(api,image,version):
 if not re.fullmatch(r'ghcr\.io/[a-z0-9-]+/todo-app@sha256:[a-f0-9]{64}',image) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-day5\.[a-z0-9]+',version):fail('RELEASE_ARTIFACT_INVALID')
 before=api.guard(api.deployment());initial_template_guard(before,api.b);old=before['spec']['template']['spec']['containers'][0]['image']
 if old not in (api.b['app_template']['spec']['containers'][0]['image'],image):fail('INITIAL_IMAGE_NOT_REVIEWED')
 template=copy.deepcopy(before['spec']['template']);desired=copy.deepcopy(template);desired['spec']['containers'][0]['image']=image;baseline=api.smoke()
 if old==image:
  api.wait_ready(image,template);return {'already_deployed':True,'image':image,**api.crud(version),**api.smoke(version)}
 issued=False
 try:
  issued=True;api.patch_image(before,image);api.wait_ready(image,desired);proof={**api.smoke(version),**api.crud(version),**api.smoke(version)}
  return {'image':image,'image_only_patch':True,'rollout_ready':True,**proof}
 except BaseException:
  if issued:
   current=api.guard(api.deployment());current_template=current['spec']['template']
   if current_template not in (template,desired):fail('ROLLBACK_CONCURRENT_CHANGE_REFUSED')
   if current_template==desired:api.patch_image(current,old)
   api.wait_ready(old,template);api.smoke(baseline['version'])
  raise

def verify_missing_artifact(image):
 owner=image.split('/')[1];digest=image.split('@',1)[1]
 opener=build_opener(ProxyHandler({}),NoRedirect(),HTTPSHandler(context=ssl.create_default_context()))
 try:
  with opener.open('https://ghcr.io/token?service=ghcr.io&scope=repository:'+owner+'/todo-app:pull',timeout=10) as r:raw=r.read(65537)
  if len(raw)>65536:fail('ANONYMOUS_TOKEN_RESPONSE_TOO_LARGE')
  token=json.loads(raw).get('token')
  if not isinstance(token,str) or not token or len(token)>32768:fail('ANONYMOUS_TOKEN_INVALID')
  request=Request('https://ghcr.io/v2/'+owner+'/todo-app/manifests/'+digest,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json'})
  try:
   with opener.open(request,timeout=10):fail('FAULT_ARTIFACT_COLLISION')
  except HTTPError as e:
   if e.code!=404:fail('FAULT_ARTIFACT_ABSENCE_UNPROVEN')
 except SafeError:raise
 except Exception:fail('FAULT_ARTIFACT_CHECK_FAILED')

def exercise_recovery(api,image,version):
 fault=image.split('@',1)[0]+'@sha256:'+hashlib.sha256(('training-ci-missing:'+version).encode()).hexdigest()
 verify_missing_artifact(fault);good=api.guard(api.deployment());initial_template_guard(good,api.b)
 if good['spec']['template']['spec']['containers'][0]['image']!=image:fail('RECOVERY_GOOD_IMAGE_DRIFT')
 template=copy.deepcopy(good['spec']['template']);bad=copy.deepcopy(template);bad['spec']['containers'][0]['image']=fault;api.smoke(version);observed=False;issued=False
 try:
  issued=True;api.patch_image(good,fault)
  try:api.wait_ready(fault,bad,budget=35)
  except SafeError as error:
   if error.args!=('ROLLOUT_TIMEOUT',):raise
   observed=True
  if not observed:fail('EXPECTED_ROLLOUT_FAILURE_NOT_OBSERVED')
  api.smoke(version)
 finally:
  if issued:
   current=api.guard(api.deployment());actual=current['spec']['template']
   if actual not in (template,bad):fail('RECOVERY_CONCURRENT_CHANGE_REFUSED')
   if actual==bad:api.patch_image(current,image)
   api.wait_ready(image,template);api.smoke(version)
 return {'controlled_unavailable_image_rollout_observed':observed,'good_image_restored':True,'fixture_preserved_after_recovery':True,'Pod_waiting_reason_not_read':True}

@contextmanager
def termination_guard():
 previous=signal.getsignal(signal.SIGTERM)
 interrupted_once=False
 def interrupted(signum,frame):
  nonlocal interrupted_once
  if not interrupted_once:
   interrupted_once=True;fail('CI_DEPLOYMENT_INTERRUPTED')
 signal.signal(signal.SIGTERM,interrupted)
 try:yield
 finally:signal.signal(signal.SIGTERM,previous)

def run(a):
 if a.ci_hosted and os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':fail('HOSTED_RUNNER_REQUIRED')
 preflight=getattr(a,'preflight_only',False)
 if preflight and (not a.ci_hosted or a.image or a.exercise_recovery):fail('PREFLIGHT_READ_ONLY_ARGUMENTS_REQUIRED')
 if not preflight and not a.image:fail('RELEASE_ARTIFACT_REQUIRED')
 b=validate_binding(json.loads(Path(a.binding).read_text()));api=API(a.config,b)
 if preflight:return hosted_preflight(api,a.version)
 result=deploy(api,a.image,a.version)
 if a.exercise_recovery:result.update(exercise_recovery(api,a.image,a.version))
 if a.ci_hosted:result['runner_environment']='github-hosted'
 return result

def main():
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--binding',required=True);p.add_argument('--image');p.add_argument('--version',required=True);p.add_argument('--exercise-recovery',action='store_true');p.add_argument('--ci-hosted',action='store_true');p.add_argument('--preflight-only',action='store_true');a=p.parse_args()
 try:
  with termination_guard():result=run(a)
  print(json.dumps(result))
 except SafeError as e:print(json.dumps({'error':e.args[0],'credential_output':False,**e.details}));raise SystemExit(1)
 except Exception:print(json.dumps({'error':'SAFE_DEPLOYMENT_FAILED','credential_output':False}));raise SystemExit(1)
if __name__=='__main__':main()

'use strict';
const $ = id => document.getElementById(id);
const shapes = {
 scan:'<path d="M8 3H4v5m12-5h4v5M4 16v5h4m12-5v5h-4M7 12h10"/>',
 link:'<path d="m10 8 2-2a4 4 0 0 1 6 6l-2 2m-2 2-2 2a4 4 0 0 1-6-6l2-2m1 5 6-6"/>',
 file:'<path d="M6 3h8l4 4v14H6zM14 3v5h4M9 14h6"/>',
 layers:'<path d="m12 3 9 5-9 5-9-5zM3 12l9 5 9-5M3 16l9 5 9-5"/>',
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v6l4 2"/>',
 globe:'<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
 arrow:'<path d="M4 12h15m-5-5 5 5-5 5"/>',
 lock:'<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>'
};
document.querySelectorAll('[data-icon]').forEach(el => {
 el.innerHTML='<svg aria-hidden="true" class="icon" viewBox="0 0 24 24">'+shapes[el.dataset.icon]+'</svg>';
});
const el = (tag, text, cls) => { const n = document.createElement(tag); if(text !== undefined)n.textContent=text; if(cls)n.className=cls; return n; };
const levels = {low:'Низкий риск', medium:'Средний риск', high:'Высокий риск'};
const states = {queued:'В очереди', running:'Выполняется', done:'Готово', failed:'Ошибка'};
const pending = row => row.status==='queued' || row.status==='running';
let watched=null, watchTimer, historyTimer;
let kind='url', busy=false;
function select(k){
 kind=k; const url=k==='url'; $('urlBox').hidden=!url; $('fileBox').hidden=url;
 $('urlTab').setAttribute('aria-pressed',url); $('fileTab').setAttribute('aria-pressed',!url);
 $('submit').children[1].textContent=url?'Проверить ссылку':'Проверить файл';
 $('detector').textContent=url?'Фишинговые сайты':'Вредоносное ПО'; $('dataset').textContent=url?'GramBeddings':'ClaMP';
 $('method').textContent=url?'Лес и фрагменты URL':'Случайный лес';
 if(url && $('urlProfile').value==='brand'){
  $('dataset').textContent='PhreshPhish';
  $('method').textContent='Случайный лес с признаками брендов';
 }
 if(url && $('urlProfile').value==='mixed'){
  $('dataset').textContent='GramBeddings, Ebbu2017, PhreshPhish';
  $('method').textContent='Структура, бренды и фрагменты URL';
 }
 $('note').textContent=url?'Анализируется структура URL без перехода на сайт.':'Анализируются заголовки PE без запуска файла.';
 $('error').textContent='';$('report').hidden=true;
}
$('urlTab').onclick=()=>select('url'); $('fileTab').onclick=()=>select('file');
$('urlProfile').onchange=()=>select('url');
async function api(path,options){
 const response=await fetch(path,options);
 const data=await response.json();
 if(!response.ok){const err=Error(data.error || 'Ошибка сервера.');err.status=response.status;throw err;}
 return data;
}
function showReport(box,row){
 box.replaceChildren(el('h3',row.name));
 if(pending(row) || row.status==='failed'){
  box.append(el('strong',states[row.status]));
  if(row.error)box.append(el('p',row.error));
  return;
 }
 box.append(el('span',levels[row.level],'risk '+row.level),
  el('p','Готово · '+row.score+' из 100 · модель '+(row.model_version || 'v1')));
 if(row.observations){
  const facts=el('dl',undefined,'detailgrid');
  for(const [key,value] of Object.entries(row.observations))facts.append(el('dt',key),el('dd',value));
  box.append(facts);
 }
 const details=el('details'); details.append(el('summary','Признаки объекта'));
 const grid=el('dl',undefined,'detailgrid'); for(const [key,value] of Object.entries(row.features))grid.append(el('dt',key),el('dd',value));
 details.append(grid);box.append(details);
}
function list(box,rows){
 box.replaceChildren();
 if(!rows.length){box.append(el('div','Проверок пока нет. Здесь появятся результаты анализа.','empty'));return;}
 for(const row of rows){
  const button=el('button',undefined,'record'), time=el('time',new Date(row.created).toLocaleString('ru-RU', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}));
  button.append(el('span',row.kind==='url'?'URL':'PE','code'),el('strong',row.name),time,el('span',levels[row.level] || states[row.status],'risk '+(row.level || '')));
  button.onclick=()=>{showReport($('detail'),row);$('dialog').dataset.scanId=row.id;$('dialog').showModal();};box.append(button);
 }
}
async function refresh(){
 clearTimeout(historyTimer);
 try{const rows=await api('/api/scans');list($('recent'),rows.slice(0,4));list($('all'),rows);
  const detail=rows.find(r=>r.id===$('dialog').dataset.scanId);
  if($('dialog').open && detail)showReport($('detail'),detail);
  if(rows.some(pending))historyTimer=setTimeout(refresh,2000);
 }catch{for(const id of ['recent','all'])$(id).textContent='Не удалось загрузить журнал.';historyTimer=setTimeout(refresh,5000);}
}
function watch(id){
 clearTimeout(watchTimer);watched=id;sessionStorage.setItem('sentra.pending',id);
 async function poll(){
  try{
   const row=await api('/api/scans/'+id);if(watched!==id)return;
   $('error').textContent='';showReport($('report'),row);$('report').hidden=false;
   if(!pending(row)){watched=null;sessionStorage.removeItem('sentra.pending');await refresh();return;}
  }catch(e){
   if(watched!==id)return;
   $('error').textContent=e.message;
   if(e.status===404){sessionStorage.removeItem('sentra.pending');watched=null;return;}
  }
  watchTimer=setTimeout(poll,1200);
 }
 poll();
}
$('close').onclick=()=>$('dialog').close();
$('form').onsubmit=async event=>{
 event.preventDefault(); if(busy)return;
 const url=kind==='url', file=$('file').files[0], address=$('url').value.trim();
 $('error').textContent='';$('report').hidden=true;
 if(url&&!address || !url&&!file){$(url?'url':'file').focus();$('error').textContent=url?'Введите адрес сайта.':'Выберите файл.';return;}
 if(!url&&file.size>10*1024*1024){$('error').textContent='Допустимый размер файла — до 10 МБ.';return;}
 busy=true; for(const id of ['submit','urlTab','fileTab','urlProfile'])$(id).disabled=true;
 $('submit').children[1].textContent='Анализируем…';
 try {
  const headers=url?{'Content-Type':'application/json'}:{'Content-Type':'application/octet-stream','X-File-Name':encodeURIComponent(file.name)};
  const row=await api('/api/scans/'+kind,{method:'POST',headers,body:url?JSON.stringify({url:address,profile:$('urlProfile').value}):file});
  showReport($('report'),row);$('report').hidden=false;$('report').focus();watch(row.id);await refresh();
 }catch(e){$('error').textContent=e.message;}
 finally{busy=false;for(const id of ['submit','urlTab','fileTab','urlProfile'])$(id).disabled=false;$('submit').children[1].textContent=url?'Проверить ссылку':'Проверить файл';}
};
function resultTable(caption, columns, rows){
 const table=el('table');table.append(el('caption',caption));
 const heading=table.createTHead().insertRow();
 for(const name of columns){const th=el('th',name);th.scope='col';heading.append(th);}
 const body=table.createTBody();
 for(const values of rows){
  const tr=body.insertRow();
  for(const value of values)tr.insertCell().textContent=value;
 }
 return table;
}
function showBenchmarks(b){
 const names={url:'Основная',url_brand:'Бренды в URL',url_mixed:'Смешанная'};
 const fmt=n=>n.toLocaleString('ru-RU',{maximumFractionDigits:1});
 const urlRows=Object.entries(b.url.arms).map(([k,arm])=>{
  const {tp,fp,fn,tn}=arm.test;
  return [names[k],fmt(arm.threshold),tp+' / '+(tp+fn),fmt(1000*fp/(fp+tn))];
 });
 const fileRows=[];
 const range=a=>a[0]===a[1]?a[0]:a.join('–');
 for(const [arch,models] of Object.entries(b.files)){
  for(const [engine,m] of Object.entries(models)){
   fileRows.push([arch.toUpperCase(),engine==='ember'?'EMBER':'Sentra',range(m.tp_range)+' / '+m.positive,range(m.fp_range)+' / '+m.negative]);
  }
 }
 $('benchmarkBody').replaceChildren(
  el('p','Пороги подобраны на валидации с бюджетом '+b.url.budget_per_1000+' ложных тревог на 1 000 легитимных адресов. Тест охватывает '+fmt(b.url.test.rows)+' адресов за '+b.url.test.start+' — '+b.url.test.end+'.'),
  resultTable('Фишинговые адреса', ['Модель','Порог','Найдено угроз','Ложных на 1 000'],urlRows),
  resultTable('Исполняемые файлы', ['Набор','Модель','Найдено угроз','Тревог среди легитимных'],fileRows),
  el('p','Диапазоны учитывают поля PE-заголовка, отсутствующие в наборе. Бюджет ложных тревог на валидации — 5%.'),
  el('p','Медианы на '+b.cost_files+' подписанных файлах Windows. Sentra — '+b.cost.sentra.ms.toLocaleString('ru-RU',{maximumFractionDigits:2})+' мс и '+fmt(b.cost.sentra.peak_rss_mib)+' МиБ пиковой памяти процесса. EMBER — '+fmt(b.cost.ember.ms)+' мс и '+fmt(b.cost.ember.peak_rss_mib)+' МиБ.'));
}
async function route(){
 const view=['history','models'].includes(location.hash.slice(1))?location.hash.slice(1):'scanner';
 document.querySelectorAll('.view').forEach(n=>n.hidden=n.id!==view);
 document.querySelectorAll('nav a').forEach(n=>{if(n.hash==='#'+view)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current');});
 if(view==='models'){
  try{const [data,bench]=await Promise.all([api('/api/models'),api('/api/benchmarks')]);$('metrics').replaceChildren();showBenchmarks(bench);
   const titles={url:'Ссылки · GramBeddings',url_brand:'Бренды в URL · PhreshPhish',url_mixed:'Смешанная модель · поздний тест',file:'Файлы · ClaMP'};
   for(const k of Object.keys(titles)){const m=data[k],card=el('article');
    card.append(el('h3',titles[k]),el('p','Обучение: '+m.train.toLocaleString('ru-RU')+' · Тест: '+m.test.toLocaleString('ru-RU')),
    el('p','Полнота: '+(100*m.tp/(m.tp+m.fn)).toFixed(1)+'% · Точность (precision): '+(100*m.tp/(m.tp+m.fp)).toFixed(1)+'%'),
    el('p','Порог высокого риска: '+m.threshold+' из 100.'),el('small','Ложные тревоги на 1 000 легитимных объектов: '+(1000*m.fp/(m.fp+m.tn)).toFixed(1)+' · Пропущено угроз: '+m.fn));$('metrics').append(card);}
  }catch{$('metrics').textContent='Не удалось загрузить метрики.';}
 }else await refresh();
}
window.addEventListener('hashchange',route);route();
const saved=sessionStorage.getItem('sentra.pending');
if(saved && /^[0-9a-f]{32}$/.test(saved))watch(saved);

// Draw a layered triangulated shield using concentric contours of its silhouette.
function drawShield(){
 const canvas=$('shield'), w=canvas.clientWidth,h=canvas.clientHeight,dpr=Math.min(devicePixelRatio,2);
 canvas.width=w*dpr;canvas.height=h*dpr;const c=canvas.getContext('2d');c.scale(dpr,dpr);
 const mobile=w<630,cx=w*(mobile?.91:.775),cy=h*.51,s=Math.min(h/247,w/640)*(mobile?.91:1);
 c.save();c.translate(cx,cy);c.scale(s,s);
 function line(x,y,a,b,color,width=1){c.strokeStyle=color;c.lineWidth=width;c.beginPath();c.moveTo(x,y);c.lineTo(a,b);c.stroke();}
 for(let x=-350;x<420;x+=22){for(let y=-160;y<160;y+=22){c.fillStyle='#ad91e62e';c.fillRect(x,y,1.6,1.6);}}
 for(const [rx,ry,r] of [[177,57,-.26],[157,93,.28],[210,82,-.19]]){
 c.beginPath();c.ellipse(0,4,rx,ry,r,0,Math.PI*2);c.strokeStyle='#ad8ce247';c.lineWidth=.85;c.stroke();}
 for(const [x,y] of [[-166,42],[144,-59],[165,42],[-106,-78]]){line(x-4,y,x+4,y,'#bea4e8');line(x,y-4,x,y+4,'#bea4e8');}
 const anchors=[[0,-97],[23,-84],[56,-77],[82,-73],[81,-43],[78,-11],[68,21],[51,49],[26,76],[0,97],[-26,78],[-49,55],[-67,26],[-77,-6],[-82,-40],[-82,-73],[-56,-78],[-26,-86]];
 const contour=anchors.flatMap(([x,y],i)=>{const next=anchors[(i+1)%anchors.length];return [[x,y],[(x+next[0])/2,(y+next[1])/2]];});
 const point=(i,t,back=0)=>{const [x,y]=contour[(i+contour.length)%contour.length];return [x*t*.97+y*t*.15+17*(1-t*t)+back,y*t*.96-x*t*.17-back*.34];};
 const border=(t,back)=>{c.beginPath();contour.forEach((_,i)=>{const p=point(i,t,back);i?c.lineTo(...p):c.moveTo(...p);});c.closePath();};
 c.shadowColor='#a17aff';c.shadowBlur=16;border(1,-11);c.fillStyle='#61479a';c.fill();c.shadowBlur=0;c.strokeStyle='#c9aaff';c.stroke();
 for(let i=0;i<contour.length;i++){const a=point(i,1,-11),b=point(i,1);line(...a,...b,'#b397ed99');}
 for(let ring=0;ring<9;ring++)for(let i=0;i<contour.length;i++){
  const f=ring/9,t=(ring+1)/9, a=point(i,f),b=point(i+1,f),d=point(i,t),e=point(i+1,t);
  for(const tri of [[a,b,e],[a,e,d]]){
   c.beginPath();c.moveTo(...tri[0]);c.lineTo(...tri[1]);c.lineTo(...tri[2]);c.closePath();
   const light=32+13*t+10*Math.sin(i*.18)+4*Math.sin(i*7.2+ring*4);
   c.fillStyle='hsl(258 42% '+light+'%)';c.fill();c.strokeStyle='rgba(214,188,255,.47)';c.lineWidth=.57;c.stroke();
  }
 }
 border(1,0);c.strokeStyle='#e1caff';c.lineWidth=1.5;c.stroke();c.restore();
}
new ResizeObserver(drawShield).observe($('shield'));

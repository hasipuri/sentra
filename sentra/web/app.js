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
 $('note').textContent=url?'Анализируется структура URL без перехода на сайт.':'Анализируются заголовки PE без запуска файла.';
 $('error').textContent='';$('report').hidden=true;
}
$('urlTab').onclick=()=>select('url'); $('fileTab').onclick=()=>select('file');
$('urlProfile').onchange=()=>select('url');
async function api(path,options){
 const response=await fetch(path,options);
 const data=await response.json(); if(!response.ok)throw Error(data.error || 'Ошибка сервера.');
 return data;
}
function showReport(box,row){
 const explanation=row.model_version==='url-brand-v1'?'Модель учитывает фрагменты адреса и расположение названий брендов.':
  (row.kind==='url'?'Учитывается только структура адреса.':'Учитываются только заголовки PE.');
 box.replaceChildren(el('h3',row.name),el('span',levels[row.level],'risk '+row.level),
 el('p','Оценка модели '+(row.model_version || 'v1')+': '+row.score+' из 100. '+explanation));
 const details=el('details'); details.append(el('summary','Признаки объекта'));
 const grid=el('dl',undefined,'detailgrid'); for(const [key,value] of Object.entries(row.features))grid.append(el('dt',key),el('dd',value));
 details.append(grid);box.append(details);
}
function list(box,rows){
 box.replaceChildren();
 if(!rows.length){box.append(el('div','Проверок пока нет. Здесь появятся результаты анализа.','empty'));return;}
 for(const row of rows){
  const button=el('button',undefined,'record'), time=el('time',new Date(row.created).toLocaleString('ru-RU', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}));
  button.append(el('span',row.kind==='url'?'URL':'PE','code'),el('strong',row.name),time,el('span',levels[row.level],'risk '+row.level));
  button.onclick=()=>{showReport($('detail'),row);$('dialog').showModal();};box.append(button);
 }
}
async function refresh(){
 try{const rows=await api('/api/scans');list($('recent'),rows.slice(0,4));list($('all'),rows);}
 catch{for(const id of ['recent','all'])$(id).textContent='Не удалось загрузить журнал.';}
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
  showReport($('report'),row);$('report').hidden=false;$('report').focus();await refresh();
 }catch(e){$('error').textContent=e.message;}
 finally{busy=false;for(const id of ['submit','urlTab','fileTab','urlProfile'])$(id).disabled=false;$('submit').children[1].textContent=url?'Проверить ссылку':'Проверить файл';}
};
async function route(){
 const view=['history','models'].includes(location.hash.slice(1))?location.hash.slice(1):'scanner';
 document.querySelectorAll('.view').forEach(n=>n.hidden=n.id!==view);
 document.querySelectorAll('nav a').forEach(n=>{if(n.hash==='#'+view)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current');});
 if(view==='models'){
  try{const data=await api('/api/models');$('metrics').replaceChildren();
   const titles={url:'Ссылки · GramBeddings',url_brand:'Бренды в URL · PhreshPhish',file:'Файлы · ClaMP'};
   for(const k of Object.keys(titles)){const m=data[k],card=el('article');
    card.append(el('h3',titles[k]),el('p','Обучение: '+m.train.toLocaleString('ru-RU')+' · Тест: '+m.test.toLocaleString('ru-RU')),
    el('p','Полнота: '+(100*m.tp/(m.tp+m.fn)).toFixed(1)+'% · Точность (precision): '+(100*m.tp/(m.tp+m.fp)).toFixed(1)+'%'),
    el('p','Порог высокого риска: '+m.threshold+' из 100.'),el('small','Ложные тревоги на 1 000 легитимных объектов: '+(1000*m.fp/(m.fp+m.tn)).toFixed(1)+' · Пропущено угроз: '+m.fn));$('metrics').append(card);}
  }catch{$('metrics').textContent='Не удалось загрузить метрики.';}
 }else await refresh();
}
window.addEventListener('hashchange',route);route();

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

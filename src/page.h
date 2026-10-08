#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1></header><div class=wrap>
<div id=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px">
⚠️ <b>Используются пароли по умолчанию.</b> <code>WEB_PASS/OTA_PASS</code> в <code>secrets.h</code> — это плейсхолдеры из публичного репозитория, их знают все. Задайте свои и перепрошейте плату.
</div>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1>Блокировка активна</b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30>30 сек</option><option value=300 selected>5 мин</option><option value=1800>30 мин</option><option value=0>пока не включу вручную</option></select>
<button id=pausebtn onclick=togglePause()>Пауза</button></div>
<div class=cards id=sys></div>
<h2>КЛИЕНТЫ</h2><table id=ct><thead><tr><th>Клиент</th><th>MAC</th><th>Заблокир.</th><th>Пропущено</th><th></th></tr></thead><tbody></tbody></table>
<h2>ПОСЛЕДНИЕ DNS-ЗАПРОСЫ</h2>
<div style="margin-bottom:6px;display:flex;justify-content:space-between;align-items:center"><span id=qday style="color:#8b949e;font-size:12px"></span>
<select id=qf style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:4px"><option value="">все запросы</option><option value=b>только заблокированные</option><option value=a>только пропущенные</option></select></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:6px">последние 128 запросов, решает плата: заблокирован (красный) или пропущен в роутер (зелёный)</div>
<table id=qt><thead><tr><th>Домен</th><th>Клиент</th><th>Решение</th><th>Когда</th></tr></thead><tbody></tbody></table>
<h2>СВОИ БЛОКИРУЕМЫЕ ДОМЕНЫ</h2>
<div style=margin-bottom:8px><input id=dom placeholder="мой-пример.net" size=30><button onclick=addDom()>Заблокировать домен</button></div>
<table id=cl><tbody></tbody></table>
<h2>РАЗРЕШЁННЫЕ ДОМЕНЫ (НЕ БЛОКИРОВАТЬ)</h2>
<div style="color:#8b949e;font-size:12px;margin-bottom:6px">имеют приоритет над списком и сохраняются при любой замене блэклиста — например, <code>youtube.com</code> вернётся из любого обновления</div>
<div style=margin-bottom:8px><input id=adom placeholder="youtube.com" size=30><button onclick=addAllowDom()>Разрешить домен</button></div>
<table id=al><tbody></tbody></table>
<h2>СПИСОК &mdash; ЗАГРУЗКА ФАЙЛА</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button>Загрузить список</button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">соберите <code>blocklist.bin</code> командой <code>tools/build_blocklist.py</code> и загрузите его сюда &mdash; без USB</div>
<h2>СПИСОК &mdash; АВТО-ОБНОВЛЕНИЕ ИЗ ИНТЕРНЕТА</h2>
<div style=margin-bottom:6px><input id=uurl placeholder="https://host/blocklist.bin" size=40> каждые <input id=uiv size=2 value=24> ч · пояс <input id=tzin size=6 placeholder="MSK-3">
<button onclick=saveUpd()>Сохранить</button> <button onclick=fetchNow()>Обновить сейчас</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">плата сама скачивает готовый <code>blocklist.bin</code> по расписанию (например, вложение GitHub Release). последнее: <span id=ustat>&mdash;</span></div>
<h2>РЕЗЕРВНАЯ КОПИЯ НАСТРОЕК</h2>
<div style=margin-bottom:18px><a href=/backup.json style="color:#58a6ff">⬇ Скачать резервную копию</a> <span style="color:#8b949e;font-size:12px">(свои и разрешённые домены, баны, обновление, пояс)</span>
<form id=rsform style="margin:8px 0"><input type=file id=rsfile accept=.json><button>Восстановить из файла</button> <span id=rsmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px">восстановление заменяет все настройки из файла; сам блэлист загружается отдельно (секция выше)</div></div>
<h2>ПРОШИВКА &mdash; ОБНОВЛЕНИЕ (OTA)</h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button>Прошить</button> <span id=fwmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">загрузите <code>.pio/build/c3/firmware.bin</code> &mdash; плата проверит файл и перезагрузится в новую прошивку</div>
<h2>WI-FI</h2>
<div style=margin-bottom:18px><button onclick="if(confirm('Забыть сохранённый Wi-Fi и перезагрузиться в режим настройки?'))forgetWifi()">Забыть Wi-Fi</button></div>
</div><script>
function fmt(n){return n.toLocaleString('ru-RU')}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent='@ '+s.ip;
credwarn.style.display=s.defcreds?'block':'none';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?'Блокировка активна':(s.resumeIn>0?'Пауза — возобновление через '+s.resumeIn+' с':'Пауза');
pausebtn.textContent=on?'Пауза':'Возобновить';pausedur.style.display=on?'':'none';
sys.innerHTML=[['Заблокировано',fmt(s.blocked),'b'],['Пропущено',fmt(s.allowed),'a'],['Доменов в списке',fmt(s.domains),''],
['Клиентов',s.clients.length,''],['Сигнал',s.rssi+' дБм',''],['Температура',s.temp+' °C',''],['RAM свободно',Math.round(s.heap/1024)+' КБ',''],['Аптайм',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>ЗАБАНЕН</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban data-ip="${c.ip}">${c.banned?'Разбанить':'Забанить'}</button></td></tr>`).join('');
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">удалить</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>пока нет</td></tr>';
al.tBodies[0].innerHTML=s.allow.map(d=>`<tr><td class=a>${esc(d)}</td><td style=text-align:right><button class=aldl data-d="${esc(d)}">удалить</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>нет — активен весь список</td></tr>';
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
if(document.activeElement!=tzin)tzin.value=s.tz||'';
if(s.today&&s.yest)qday.textContent='сегодня: '+fmt(s.today.blk)+' заблокировано / '+fmt(s.today.alw)+' пропущено · вчера: '+fmt(s.yest.blk)+' / '+fmt(s.yest.alw);
ustat.textContent=s.upstat||'—';loadQlog();}
let qlast=null,qlfail=0;
async function loadQlog(){if(qlfail)return;try{qlast=await(await fetch('/qlog.json',{headers:CSRF_HDRS})).json();renderQlog();}catch(_){qlfail=1;}}   // 401 until authenticated once — stop polling, reload re-enables
function renderQlog(){if(!qlast)return;let fl=qf.value;
qt.tBodies[0].innerHTML=qlast.entries.filter(e=>!fl||(fl=='b'?e.b:!e.b)).reverse().map(e=>`<tr><td>${esc(e.d)}</td><td>${e.ip}</td><td class="${e.b?'b':'a'}">${e.b?'заблокирован':'пропущен'}</td><td>${e.age} с назад</td></tr>`).join('')||'<tr><td style=color:#8b949e>пока нет</td></tr>';}
qf.onchange=renderQlog;
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
function addAllowDom(){let d=adom.value.trim();if(d){fetch('/addallow?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{adom.value='';load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
al.addEventListener('click',e=>{if(e.target.classList.contains('aldl'))fetch('/delallow?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24)+'&tz='+encodeURIComponent(tzin.value.trim()),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent='загружаю…';fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='прошиваю '+(f.size/1048576).toFixed(2)+' МБ…';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?'✓ перезагрузка, подключитесь через ~15 с':'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ перезагрузка, подключитесь через ~15 с';}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='загружаю '+(f.size/1048576).toFixed(2)+' МБ…';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?'✓ обновлено':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ ошибка загрузки';}
blf.value='';setTimeout(load,600);};
rsform.onsubmit=async e=>{e.preventDefault();let f=rsfile.files[0];if(!f)return;rsmsg.textContent='восстанавливаю…';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/restore',{method:'POST',headers:CSRF_HDRS,body:fd});rsmsg.textContent=await r.text();}
catch(_){rsmsg.textContent='✗ ошибка загрузки';}
rsfile.value='';setTimeout(load,600);};
load();setInterval(load,3000);
</script></body></html>)HTML";
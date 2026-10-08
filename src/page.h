#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).
// Bilingual (RU/EN): static text carries data-i / data-i-html / data-i-ph keys
// resolved from the I dictionary by setLang(); dynamic JS strings use t().
// Layout: blocking bar + tabs (Overview / DNS log / Clients / Lists / Settings).
// "uplast" (NTP wall-clock stamp of the last successful blocklist swap) comes
// from /stats.json and is shown on the Overview card and the Lists tab.

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;position:sticky;top:0;z-index:5}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.langs{display:flex;gap:6px}.lbtn{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px;font-weight:600}.lbtn.on{background:#3fb950;color:#000;border-color:#3fb950}
#blockbar{display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:10px}
#qday{margin:-6px 0 14px;color:#8b949e;font-size:13px}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
.tab{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:8px;padding:7px 14px;cursor:pointer;font:600 13px system-ui}
.tab.on{background:#3fb950;color:#000;border-color:#3fb950}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}.card .lm{color:#8b949e;font-size:11px;margin-top:4px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px}
.sec{display:none}.sec.on{display:block}
h2{font-size:13px;letter-spacing:.06em;color:#8b949e;margin:22px 0 8px;text-transform:uppercase}
.muted{color:#8b949e;font-size:12px;margin-bottom:6px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:5px 10px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}
input,select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:6px}
form{margin-bottom:6px}
.hint{display:block;padding:0 2px}
@media(max-width:640px){.cards{flex-direction:column}}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1>
<div class=langs><button class=lbtn on id=btn-en onclick=setLang('en')>EN</button><button class=lbtn id=btn-ru onclick=setLang('ru')>РУ</button></div></header><div class=wrap>
<div id=cw data-i-html=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:13px">⚠️ <b>Используются пароли по умолчанию.</b> <code>WEB_PASS/OTA_PASS</code> в <code>secrets.h</code> — это плейсхолдеры из публичного репозитория, их знают все. Задайте свои и перепрошейте плату.</div>
<div id=blockbar>
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1>Блокировка активна</b>
<select id=pausedur><option value=30 data-i=pau30>30 сек</option><option value=300 selected data-i=pau300>5 мин</option><option value=1800 data-i=pau1800>30 мин</option><option value=0 data-i=pau0>пока не включу вручную</option></select>
<button id=pausebtn onclick=togglePause()>Пауза</button></div>
<div id=qday></div>

<nav class=tabs>
<button class="tab on" data-tab=ov onclick=showTab('ov') data-i=tabOverview>📊 Обзор</button>
<button class=tab data-tab=log onclick=showTab('log') data-i=tabLog>📜 Журнал</button>
<button class=tab data-tab=clients onclick=showTab('clients') data-i=tabClients>👥 Клиенты</button>
<button class=tab data-tab=lists onclick=showTab('lists') data-i=tabLists>🚫 Списки</button>
<button class=tab data-tab=set onclick=showTab('set') data-i=tabSettings>⚙️ Настройки</button>
</nav>

<section class="sec on" id=sec-ov>
<div class=cards id=sys></div>
</section>

<section class=sec id=sec-log>
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;gap:10px;flex-wrap:wrap">
<span class=muted data-i=qNote>последние 128 запросов, решает плата: заблокирован (красный) или пропущен в роутер (зелёный)</span>
<select id=qf><option value="" data-i=qfAll>все запросы</option><option value=b data-i=qfBlocked>только заблокированные</option><option value=a data-i=qfAllowed>только пропущенные</option></select></div>
<table id=qt><thead><tr><th data-i=thDomain>Домен</th><th data-i=thClient>Клиент</th><th data-i=thVerdict>Решение</th><th data-i=thWhen>Когда</th></tr></thead><tbody></tbody></table>
</section>

<section class=sec id=sec-clients>
<table id=ct><thead><tr><th data-i=thClient>Клиент</th><th data-i=thMac>MAC</th><th data-i=thBlk>Заблокир.</th><th data-i=thAllowCnt>Пропущено</th><th></th></tr></thead><tbody></tbody></table>
</section>

<section class=sec id=sec-lists>
<h2 data-i=hUpdate>СПИСОК — АВТО-ОБНОВЛЕНИЕ ИЗ ИНТЕРНЕТА</h2>
<div><input id=uurl placeholder="https://host/blocklist.bin" size=42 data-i-ph=uurlPh> каждые <input id=uiv size=2 value=24 style=width:48px> ч · пояс <input id=tzin size=6 placeholder="MSK-3" data-i-ph=tzinPh style=width:76px>
<button onclick=saveUpd() data-i=saveBtn>Сохранить</button> <button onclick=fetchNow() data-i=nowBtn>Обновить сейчас</button></div>
<div class=muted><span data-i-html=updNote></span> <span id=ustat>&mdash;</span></div>
<div class=muted id=upfull></div>
<h2 data-i=hUpload>СПИСОК — ЗАГРУЗКА ФАЙЛА</h2>
<form id=upf><input type=file id=blf accept=.bin><button data-i=uploadBtn>Загрузить список</button> <span id=upmsg class=muted></span></form>
<div class=muted data-i-html=upNote>соберите <code>blocklist.bin</code> командой <code>tools/build_blocklist.py</code> и загрузите его сюда &mdash; без USB</div>
<h2 data-i=hCustom>СВОИ БЛОКИРУЕМЫЕ ДОМЕНЫ</h2>
<div style=margin-bottom:8px><input id=dom placeholder="мой-пример.net" size=30 data-i-ph=domPh><button onclick=addDom() data-i=addDomBtn>Заблокировать домен</button></div>
<table id=cl><tbody></tbody></table>
<h2 data-i=hAllow>РАЗРЕШЁННЫЕ ДОМЕНЫ (НЕ БЛОКИРОВАТЬ)</h2>
<div class=muted data-i-html=allowNote>имеют приоритет над списком и сохраняются при любой замене блэклиста — например, <code>youtube.com</code> вернётся из любого обновления</div>
<div style=margin-bottom:8px><input id=adom placeholder="youtube.com" size=30 data-i-ph=adomPh><button onclick=addAllowDom() data-i=addAllowBtn>Разрешить домен</button></div>
<table id=al><tbody></tbody></table>
</section>

<section class=sec id=sec-set>
<h2 data-i=hBackup>РЕЗЕРВНАЯ КОПИЯ НАСТРОЕК</h2>
<div><a href=/backup.json style="color:#58a6ff" data-i=backupLink>⬇ Скачать резервную копию</a> <span class=muted data-i=backupNote>(свои и разрешённые домены, баны, обновление, пояс)</span></div>
<form id=rsform style="margin:8px 0"><input type=file id=rsfile accept=.json><button data-i=restoreBtn>Восстановить из файла</button> <span id=rsmsg class=muted></span></form>
<div class=muted data-i-html=restoreNote>восстановление заменяет все настройки из файла; сам блэлист загружается отдельно (секция выше)</div>
<h2 data-i=hFw>ПРОШИВКА — ОБНОВЛЕНИЕ (OTA)</h2>
<form id=fwf><input type=file id=fwb accept=.bin><button data-i=flashBtn>Прошить</button> <span id=fwmsg class=muted></span></form>
<div class=muted data-i-html=fwNote>загрузите <code>.pio/build/c3/firmware.bin</code> &mdash; плата проверит файл и перезагрузится в новую прошивку</div>
<h2 data-i=hWifi>WI-FI</h2>
<div style=margin-bottom:18px><button onclick=forgetWifiIf() data-i=forgetBtn>Забыть Wi-Fi</button></div>
</section>

</div><script>
const I={en:{
tabOverview:'📊 Overview',tabLog:'📜 DNS log',tabClients:'👥 Clients',tabLists:'🚫 Lists',tabSettings:'⚙️ Settings',
pau30:'30 s',pau300:'5 min',pau1800:'30 min',pau0:'until I enable it manually',
hClients:'CLIENTS',hQlog:'RECENT DNS QUERIES',hCustom:'CUSTOM BLOCKED DOMAINS',hAllow:'ALLOWED DOMAINS (DO NOT BLOCK)',hUpload:'BLOCKLIST — UPLOAD FILE',hUpdate:'BLOCKLIST — INTERNET AUTO-UPDATE',hBackup:'SETTINGS BACKUP',hFw:'FIRMWARE — UPDATE (OTA)',hWifi:'WI-FI',
thClient:'Client',thMac:'MAC',thBlk:'Blocked',thAllowCnt:'Allowed',thDomain:'Domain',thVerdict:'Decision',thWhen:'When',
qfAll:'all queries',qfBlocked:'blocked only',qfAllowed:'allowed only',
qNote:'last 128 queries; the board decides: blocked (red) or passed to router (green)',
addDomBtn:'Block domain',domPh:'my-example.net',addAllowBtn:'Allow domain',adomPh:'youtube.com',allowNote:'take priority over the list and survive any blocklist replacement — e.g. <code>youtube.com</code> comes back from any update',
uploadBtn:'Upload list',upNote:'build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code> and upload it here — no USB needed; the swap keeps the 64 KB space check from the firmware',
saveBtn:'Save',nowBtn:'Update now',updNote:'the board downloads a ready <code>blocklist.bin</code> on a schedule (e.g. a GitHub Release asset). last attempt:',
backupLink:'⬇ Download settings backup',backupNote:'(custom &amp; allowed domains, bans, update, timezone)',restoreBtn:'Restore from file',restoreNote:'restore replaces all settings from the file; the blocklist itself is uploaded separately (section above)',
flashBtn:'Flash',fwNote:'upload <code>.pio/build/c3/firmware.bin</code> — the board verifies the file and reboots into the new firmware',
forgetBtn:'Forget Wi-Fi',forgetConfirm:'Forget the saved Wi-Fi and reboot into setup mode?',
credwarn:'⚠️ <b>Default passwords are in use.</b> <code>WEB_PASS/OTA_PASS</code> in <code>secrets.h</code> are placeholders from the public repo that everyone knows. Set your own and reflash the board.',
blockActive:'Blocking active',blockPauseIn:'Paused — resumes in {n} s',blockPause:'Paused',pauseBtn:'Pause',resumeBtn:'Resume',
cBlocked:'Blocked',cAllowed:'Allowed',cDomains:'Domains in list',cClients:'Clients',cSignal:'Signal',cTemp:'Temperature',cHeap:'RAM free',cUptime:'Uptime',rssiUnit:' dBm',tempUnit:' °C',ramUnit:' KB',
banned:'BANNED',banBtn:'Ban',unbanBtn:'Unban',rmBtn:'delete',custEmpty:'none yet',allowEmpty:'none — the whole list is active',
qBlocked:'blocked',qPassed:'passed',qEmpty:'none yet',sAgo:'s ago',qdayBody:'today: {b} blocked / {a} allowed · yesterday: {b2} / {a2}',
lastUpd:'list updated',lastUpdNever:'never',
updLoading:'downloading…',flashUp:'flashing {mb} MB…',flashOk:'✓ rebooting, reconnect in ~15 s',flashErrPre:'✗ ',upMsgUpload:'uploading {mb} MB…',upOk:'✓ updated',upErr:'✗ upload error',restMsg:'restoring…'
},ru:{
tabOverview:'📊 Обзор',tabLog:'📜 Журнал',tabClients:'👥 Клиенты',tabLists:'🚫 Списки',tabSettings:'⚙️ Настройки',
pau30:'30 сек',pau300:'5 мин',pau1800:'30 мин',pau0:'пока не включу вручную',
hClients:'КЛИЕНТЫ',hQlog:'ПОСЛЕДНИЕ DNS-ЗАПРОСЫ',hCustom:'СВОИ БЛОКИРУЕМЫЕ ДОМЕНЫ',hAllow:'РАЗРЕШЁННЫЕ ДОМЕНЫ (НЕ БЛОКИРОВАТЬ)',hUpload:'СПИСОК — ЗАГРУЗКА ФАЙЛА',hUpdate:'СПИСОК — АВТО-ОБНОВЛЕНИЕ ИЗ ИНТЕРНЕТА',hBackup:'РЕЗЕРВНАЯ КОПИЯ НАСТРОЕК',hFw:'ПРОШИВКА — ОБНОВЛЕНИЕ (OTA)',hWifi:'WI-FI',
thClient:'Клиент',thMac:'MAC',thBlk:'Заблокир.',thAllowCnt:'Пропущено',thDomain:'Домен',thVerdict:'Решение',thWhen:'Когда',
qfAll:'все запросы',qfBlocked:'только заблокированные',qfAllowed:'только пропущенные',
qNote:'последние 128 запросов, решает плата: заблокирован (красный) или пропущен в роутер (зелёный)',
addDomBtn:'Заблокировать домен',domPh:'мой-пример.net',addAllowBtn:'Разрешить домен',adomPh:'youtube.com',allowNote:'имеют приоритет над списком и сохраняются при любой замене блэклиста — например, <code>youtube.com</code> вернётся из любого обновления',
uploadBtn:'Загрузить список',upNote:'соберите <code>blocklist.bin</code> командой <code>tools/build_blocklist.py</code> и загрузите его сюда — без USB; обмен проверяет свободное место (запас 64 КБ)',
saveBtn:'Сохранить',nowBtn:'Обновить сейчас',updNote:'плата сама скачивает готовый <code>blocklist.bin</code> по расписанию (например, вложение GitHub Release). последняя попытка:',
backupLink:'⬇ Скачать резервную копию',backupNote:'(свои и разрешённые домены, баны, обновление, пояс)',restoreBtn:'Восстановить из файла',restoreNote:'восстановление заменяет все настройки из файла; сам блэлист загружается отдельно (секция выше)',
flashBtn:'Прошить',fwNote:'загрузите <code>.pio/build/c3/firmware.bin</code> — плата проверит файл и перезагрузится в новую прошивку',
forgetBtn:'Забыть Wi-Fi',forgetConfirm:'Забыть сохранённый Wi-Fi и перезагрузиться в режим настройки?',
credwarn:'⚠️ <b>Используются пароли по умолчанию.</b> <code>WEB_PASS/OTA_PASS</code> в <code>secrets.h</code> — это плейсхолдеры из публичного репозитория, их знают все. Задайте свои и перепрошейте плату.',
blockActive:'Блокировка активна',blockPauseIn:'Пауза — возобновление через {n} с',blockPause:'Пауза',pauseBtn:'Пауза',resumeBtn:'Возобновить',
cBlocked:'Заблокировано',cAllowed:'Пропущено',cDomains:'Доменов в списке',cClients:'Клиентов',cSignal:'Сигнал',cTemp:'Температура',cHeap:'RAM свободно',cUptime:'Аптайм',rssiUnit:' дБм',tempUnit:' °C',ramUnit:' КБ',
banned:'ЗАБАНЕН',banBtn:'Забанить',unbanBtn:'Разбанить',rmBtn:'удалить',custEmpty:'пока нет',allowEmpty:'нет — активен весь список',
qBlocked:'заблокирован',qPassed:'пропущен',qEmpty:'пока нет',sAgo:'с назад',qdayBody:'сегодня: {b} заблокировано / {a} пропущено · вчера: {b2} / {a2}',
lastUpd:'список обновлён',lastUpdNever:'ещё не обновлялся',
updLoading:'загружаю…',flashUp:'прошиваю {mb} МБ…',flashOk:'✓ перезагрузка, подключитесь через ~15 с',flashErrPre:'✗ ',upMsgUpload:'загружаю {mb} МБ…',upOk:'✓ обновлено',upErr:'✗ ошибка загрузки',restMsg:'восстанавливаю…'
}};
let l='ru';try{l=localStorage.getItem('c3adblock-lang')||'ru'}catch(e){}
function t(k){return (I[l]&&I[l][k])||k}
function setLang(nl){l=nl;try{localStorage.setItem('c3adblock-lang',l)}catch(e){}
document.querySelectorAll('[data-i]').forEach(el=>el.textContent=t(el.dataset.i));
document.querySelectorAll('[data-i-html]').forEach(el=>el.innerHTML=t(el.dataset.iHtml));
document.querySelectorAll('[data-i-ph]').forEach(el=>el.placeholder=t(el.dataset.iPh));
document.querySelectorAll('.lbtn').forEach(b=>b.classList.toggle('on',b.dataset.l===l));
load();}
function fmt(n){return n.toLocaleString(l==='ru'?'ru-RU':'en-US')}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
function showTab(t){document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('on',b.dataset.tab===t));document.querySelectorAll('.sec').forEach(s=>s.classList.toggle('on',s.id==='sec-'+t));}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent='@ '+s.ip;
cw.style.display=s.defcreds?'block':'none';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?t('blockActive'):(s.resumeIn>0?t('blockPauseIn').replace('{n}',s.resumeIn):t('blockPause'));
pausebtn.textContent=on?t('pauseBtn'):t('resumeBtn');pausedur.style.display=on?'':'none';
let lastUpd=(s.uplast&&s.uplast.length)?t('lastUpd')+': '+s.uplast:t('lastUpdNever');
upfull.textContent=t('lastUpd')+': '+(s.uplast&&s.uplast.length?s.uplast:t('lastUpdNever'));
const cvs=[[t('cBlocked'),fmt(s.blocked),'b',''],[t('cAllowed'),fmt(s.allowed),'a',''],
[t('cDomains'),fmt(s.domains),'',lastUpd],
[t('cClients'),s.clients.length,'',''],[t('cSignal'),s.rssi+' '+t('rssiUnit'),'',''],
[t('cTemp'),s.temp+t('tempUnit'),'',''],[t('cHeap'),Math.round(s.heap/1024)+' '+t('ramUnit'),'',''],[t('cUptime'),s.uptime,'','']];
sys.innerHTML=cvs.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div>${c[3]?`<div class=lm>${c[3]}</div>`:''}</div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>'+t('banned')+'</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td style=text-align:right><button class=ban data-ip="${c.ip}">${c.banned?t('unbanBtn'):t('banBtn')}</button></td></tr>`).join('')||`<tr><td style=color:#8b949e>${t('qEmpty')}</td></tr>`;
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">${t('rmBtn')}</button></td></tr>`).join('')||`<tr><td style=color:#8b949e>${t('custEmpty')}</td></tr>`;
al.tBodies[0].innerHTML=s.allow.map(d=>`<tr><td class=a>${esc(d)}</td><td style=text-align:right><button class=aldl data-d="${esc(d)}">${t('rmBtn')}</button></td></tr>`).join('')||`<tr><td style=color:#8b949e>${t('allowEmpty')}</td></tr>`;
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
if(document.activeElement!=tzin)tzin.value=s.tz||'';
if(s.today&&s.yest)qday.textContent=t('qdayBody').replace('{b}',fmt(s.today.blk)).replace('{a}',fmt(s.today.alw)).replace('{b2}',fmt(s.yest.blk)).replace('{a2}',fmt(s.yest.alw));
ustat.textContent=s.upstat||'—';loadQlog();}
let qlast=null,qlfail=0;
async function loadQlog(){if(qlfail)return;try{qlast=await(await fetch('/qlog.json',{headers:CSRF_HDRS})).json();renderQlog();}catch(_){qlfail=1;}}   // 401 until authenticated once — stop polling, reload re-enables
function renderQlog(){if(!qlast)return;let fl=qf.value;
qt.tBodies[0].innerHTML=qlast.entries.filter(e=>!fl||(fl=='b'?e.b:!e.b)).reverse().map(e=>`<tr><td>${esc(e.d)}</td><td>${e.ip}</td><td class="${e.b?'b':'a'}">${e.b?t('qBlocked'):t('qPassed')}</td><td>${e.age} ${t('sAgo')}</td></tr>`).join('')||`<tr><td style=color:#8b949e>${t('qEmpty')}</td></tr>`;}
qf.onchange=renderQlog;
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
function addAllowDom(){let d=adom.value.trim();if(d){fetch('/addallow?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{adom.value='';load()})}}
function forgetWifiIf(){if(confirm(t('forgetConfirm')))forgetWifi()}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
al.addEventListener('click',e=>{if(e.target.classList.contains('aldl'))fetch('/delallow?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24)+'&tz='+encodeURIComponent(tzin.value.trim()),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent=t('updLoading');fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(txt=>{ustat.textContent=txt;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(txt=>alert(txt))}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent=t('flashUp').replace('{mb}',(f.size/1048576).toFixed(2));
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?t('flashOk'):t('flashErrPre')+await r.text();}
catch(_){fwmsg.textContent=t('flashOk');}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent=t('upMsgUpload').replace('{mb}',(f.size/1048576).toFixed(2));
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?t('upOk'):'✗ '+await r.text();}
catch(_){upmsg.textContent=t('upErr');}
blf.value='';setTimeout(load,600);};
rsform.onsubmit=async e=>{e.preventDefault();let f=rsfile.files[0];if(!f)return;rsmsg.textContent=t('restMsg');
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/restore',{method:'POST',headers:CSRF_HDRS,body:fd});rsmsg.textContent=await r.text();}
catch(_){rsmsg.textContent='✗';}
rsfile.value='';setTimeout(load,600);};
setLang(l);setInterval(load,3000);
</script></body></html>)HTML";
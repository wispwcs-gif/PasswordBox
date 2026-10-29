'use strict';

// SecureBox: browser-only, dependency-free encrypted vault.
// The user's vault key is derived only in this browser and NEVER sent to Supabase.
const STORAGE_KEY = 'securebox.encrypted.vault.v1';
const SESSION_KEY = 'securebox.cloud.session.v1';
const LAST_MODE_KEY = 'securebox.last.mode.v1';
const KDF_ITERATIONS = 600_000;
const AUTO_LOCK_MS = 5 * 60 * 1000;
const ENVELOPE_AAD = new TextEncoder().encode('SecureBox:envelope:v1');
const CATEGORY_NAMES = ['Все', 'Избранное', 'Соцсети', 'Почта', 'Работа', 'Финансы', 'Развлечения', 'Другое'];
const config = Object.freeze(window.SECUREBOX_CONFIG || {});
const cloudReady = /^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/i.test(String(config.supabaseUrl || ''))
  && /^(sb_publishable_|eyJ)[a-zA-Z0-9_.-]+$/.test(String(config.publishableKey || ''));
const cloudUrl = cloudReady ? String(config.supabaseUrl).replace(/\/$/, '') : '';
const apiKey = cloudReady ? String(config.publishableKey) : '';
const $ = id => document.getElementById(id);
const state = {
  mode: sessionStorage.getItem(LAST_MODE_KEY) === 'cloud' && cloudReady ? 'cloud' : 'local',
  session: null, stage: 'master', payload: null, version: 0,
  items: [], masterKey: null, selectedCategory: 'Все', query: '',
  busy: false, editingId: null, revealed: new Map(), lastActivity: Date.now()
};

function toast(message, isError = false) {
  const el = document.createElement('div');
  el.className = `toast${isError ? ' error' : ''}`;
  el.textContent = message;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 4700);
}
function niceError(error) {
  if (!navigator.onLine) return 'Нет соединения с интернетом.';
  const msg = String(error?.message || error || 'Неизвестная ошибка');
  if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) return 'Не удалось подключиться к серверу. Проверьте адрес Supabase и интернет.';
  if (/invalid login credentials/i.test(msg)) return 'Неверный e-mail или пароль аккаунта.';
  if (/email not confirmed/i.test(msg)) return 'Сначала подтвердите e-mail по ссылке из письма.';
  if (/rate limit/i.test(msg)) return 'Слишком много попыток. Повторите позже.';
  if (/relation .* does not exist|could not find the table|schema cache/i.test(msg)) return 'Таблица облачного сейфа ещё не создана. Выполните supabase.sql.';
  return msg.slice(0, 180);
}
function busy(flag) {
  state.busy = flag;
  document.querySelectorAll('button[type="submit"],#cloudSignUpButton,#importButton,#exportButton').forEach(button => {
    button.disabled = flag;
  });
}
function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 16384) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 16384));
  }
  return btoa(binary);
}
function base64ToBytes(encoded) {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}
function isValidEnvelope(value) {
  if (!value || typeof value !== 'object' || value.version !== 1 || value.algorithm !== 'AES-256-GCM') return false;
  if (value.kdf !== 'PBKDF2-SHA-256' || !Number.isInteger(value.iterations) || value.iterations < 300_000 || value.iterations > 2_000_000) return false;
  if (![value.salt, value.iv, value.data].every(x => typeof x === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(x))) return false;
  try { return base64ToBytes(value.salt).length === 16 && base64ToBytes(value.iv).length === 12 && base64ToBytes(value.data).length >= 16; }
  catch { return false; }
}
async function deriveKey(password, salt, iterations) {
  const raw = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  raw.fill(0);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations}, baseKey, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}
async function encryptVault(items, key, template = null) {
  const salt = template ? template.salt : bytesToBase64(randomBytes(16));
  const iterations = template ? template.iterations : KDF_ITERATIONS;
  const iv = randomBytes(12);
  const plaintext = new TextEncoder().encode(JSON.stringify({items, format:1}));
  const encrypted = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:ENVELOPE_AAD},key,plaintext);
  plaintext.fill(0);
  return {version:1,algorithm:'AES-256-GCM',kdf:'PBKDF2-SHA-256',iterations,salt,iv:bytesToBase64(iv),data:bytesToBase64(new Uint8Array(encrypted))};
}
async function decryptVault(envelope, key) {
  if (!isValidEnvelope(envelope)) throw new Error('Некорректный формат зашифрованного сейфа.');
  try {
    const raw = await crypto.subtle.decrypt({name:'AES-GCM',iv:base64ToBytes(envelope.iv),additionalData:ENVELOPE_AAD},key,base64ToBytes(envelope.data));
    const obj = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
    if (!obj || obj.format !== 1 || !Array.isArray(obj.items) || obj.items.length > 20000) throw new Error('Некорректное содержимое сейфа.');
    return obj.items.filter(isValidItem);
  } catch (e) {
    if (e.name === 'OperationError') throw new Error('Неправильный мастер-пароль или повреждённые данные.');
    throw e;
  }
}
function isValidItem(x) {
  return x && typeof x.id === 'string' && x.id.length < 100 && typeof x.name === 'string' && typeof x.password === 'string'
    && typeof x.login === 'string' && typeof x.category === 'string' && typeof x.url === 'string'
    && typeof x.note === 'string' && typeof x.favorite === 'boolean';
}
async function apiRequest(path, {method='GET', body, headers={}} = {}, retry = true) {
  if (!state.session?.access_token) throw new Error('Требуется войти в аккаунт.');
  let response = await fetch(`${cloudUrl}${path}`, {
    method,
    headers: {'apikey':apiKey,'Authorization':`Bearer ${state.session.access_token}`,'Content-Type':'application/json',...headers},
    ...(body === undefined ? {} : {body:JSON.stringify(body)})
  });
  if (response.status === 401 && retry) {
    await refreshSession();
    response = await fetch(`${cloudUrl}${path}`, {
      method,
      headers:{'apikey':apiKey,'Authorization':`Bearer ${state.session.access_token}`,'Content-Type':'application/json',...headers},
      ...(body === undefined ? {} : {body:JSON.stringify(body)})
    });
  }
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.msg || data?.message || data?.error_description || data?.error || `HTTP ${response.status}`);
  return data;
}
async function authRequest(path, body) {
  const res = await fetch(`${cloudUrl}${path}`,{method:'POST',headers:{'apikey':apiKey,'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.msg || data.message || data.error_description || data.error || `HTTP ${res.status}`);
  return data;
}
function saveSession(session) {
  if (!session?.access_token || !session?.refresh_token || !session?.user?.id) throw new Error('Не удалось получить сессию.');
  state.session = session;
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  $('accountInfo').textContent = session.user.email || 'Облачный аккаунт';
}
async function refreshSession() {
  const token = state.session?.refresh_token;
  if (!token) throw new Error('Сессия истекла. Войдите в аккаунт заново.');
  const data = await authRequest('/auth/v1/token?grant_type=refresh_token',{refresh_token:token});
  saveSession(data);
}
async function fetchRemote() {
  const id = state.session.user.id;
  const rows = await apiRequest(`/rest/v1/securebox_vaults?user_id=eq.${encodeURIComponent(id)}&select=version,payload`);
  if (!Array.isArray(rows)) throw new Error('Не удалось прочитать сейф.');
  return rows.length ? {payload:rows[0].payload, version:rows[0].version} : {payload:null,version:0};
}
async function loadVaultEnvelope() {
  if (state.mode === 'local') {
    const saved = localStorage.getItem(STORAGE_KEY);
    state.payload = saved ? JSON.parse(saved) : null;
    state.version = Number(localStorage.getItem(`${STORAGE_KEY}.version`) || 0);
  } else {
    const remote = await fetchRemote();
    state.payload = remote.payload;
    state.version = Number(remote.version);
  }
  if (state.payload && !isValidEnvelope(state.payload)) throw new Error('Данные сейфа повреждены или неподдерживаемого формата.');
}
async function persistEnvelope(payload) {
  if (state.mode === 'local') {
    const currentVersion = Number(localStorage.getItem(`${STORAGE_KEY}.version`) || 0);
    if (currentVersion !== state.version) throw new Error('Сейф изменён в другой вкладке. Заблокируйте и откройте его снова.');
    localStorage.setItem(STORAGE_KEY,JSON.stringify(payload));
    localStorage.setItem(`${STORAGE_KEY}.version`,String(state.version + 1));
    state.version += 1;
    return;
  }
  const id = state.session.user.id;
  let rows;
  if (state.version === 0) {
    try {
      rows = await apiRequest('/rest/v1/securebox_vaults', {
        method:'POST',body:{user_id:id,payload,version:1},headers:{Prefer:'return=representation'}
      });
    } catch (error) {
      if (/duplicate key|409|conflict/i.test(String(error.message))) throw new Error('Сейф уже создан на другом устройстве. Выполните повторный вход.');
      throw error;
    }
  } else {
    rows = await apiRequest(`/rest/v1/securebox_vaults?user_id=eq.${encodeURIComponent(id)}&version=eq.${state.version}`,{
      method:'PATCH',body:{payload,version:state.version+1},headers:{Prefer:'return=representation'}
    });
    if (!rows.length) throw new Error('На другом устройстве сейф изменился. Нажмите «Обновить» и повторите действие.');
  }
  if (!Array.isArray(rows) || rows.length !== 1) throw new Error('Сервер не подтвердил сохранение данных.');
  state.version = Number(rows[0].version);
}
async function persistItems(nextItems) {
  if (state.busy) return false;
  busy(true);
  try {
    const envelope = await encryptVault(nextItems,state.masterKey,state.payload);
    await persistEnvelope(envelope);
    state.items = nextItems;
    state.payload = envelope;
    state.lastActivity = Date.now();
    renderItems();
    return true;
  } catch (e) {toast(niceError(e),true);return false;}
  finally {busy(false);}
}
function setMode(mode) {
  if (state.busy || state.stage === 'vault') return;
  state.mode = mode;
  state.payload = null;
  state.version = 0;
  state.masterKey = null;
  state.items = [];
  if (mode === 'local') {
    state.session = null;
    localOnlyLoad();
  } else {
    const saved = sessionStorage.getItem(SESSION_KEY);
    state.session = saved && cloudReady ? safeJSON(saved) : null;
    if (state.session?.access_token) {
      loadVaultEnvelope().catch(e => {toast(niceError(e),true);state.session=null;renderWelcome();}).finally(renderWelcome);
    }
  }
  sessionStorage.setItem(LAST_MODE_KEY,mode);
  renderWelcome();
}
function safeJSON(s) {try{return JSON.parse(s);}catch{return null;}}
function localOnlyLoad() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    state.payload = stored ? JSON.parse(stored) : null;
    state.version = Number(localStorage.getItem(`${STORAGE_KEY}.version`) || 0);
    if (state.payload && !isValidEnvelope(state.payload)) throw new Error('Повреждённая локальная запись.');
  } catch(e) {state.payload={invalid:true};toast(niceError(e),true);}
}
function renderWelcome() {
  if (state.stage === 'vault') return;
  $('welcome').classList.remove('hidden');
  $('appView').classList.add('hidden');
  $('localModeButton').classList.toggle('active',state.mode === 'local');
  $('cloudModeButton').classList.toggle('active',state.mode === 'cloud');
  const accountRequired = state.mode === 'cloud' && !state.session;
  $('cloudForm').classList.toggle('hidden',!accountRequired || !cloudReady);
  $('unlockForm').classList.toggle('hidden',accountRequired || (state.mode === 'cloud' && !cloudReady));
  $('backToCloud').classList.toggle('hidden',state.mode !== 'cloud' || !state.session);
  $('restoreAtWelcome').classList.toggle('hidden',accountRequired);
  $('welcomeTitle').textContent = accountRequired ? 'Облачный аккаунт' : (state.payload ? 'Откройте ваш сейф' : 'Создайте свой сейф');
  $('welcomeSubtitle').textContent = accountRequired ? 'Войдите, чтобы получить зашифрованные записи на любом устройстве.' : (state.payload ? 'Введите мастер-пароль для расшифровки.' : 'Придумайте длинный уникальный мастер-пароль.');
  $('modeHint').textContent = state.mode === 'local'
    ? 'Локальное шифрование. Эти данные остаются только в данном браузере и не синхронизируются.'
    : (cloudReady ? (state.session ? 'Вы вошли в облачный аккаунт. Для открытия нужен отдельный мастер-пароль.' : 'Облачные записи шифруются до отправки на сервер.') : 'Облако пока не подключено: заполните config.js и выполните supabase.sql из архива.');
  const creating = !state.payload;
  $('masterConfirmLabel').classList.toggle('hidden',!creating);
  $('masterConfirm').required = creating && !accountRequired;
  $('unlockButton').textContent = creating ? 'Создать зашифрованный сейф' : 'Разблокировать';
  $('masterPassword').placeholder = creating ? 'Минимум 12 символов' : 'Ваш мастер-пароль';
  $('masterPassword').value = '';
  $('masterConfirm').value = '';
}
async function accountAction(action) {
  if (!cloudReady) return toast('Для синхронизации сначала настройте Supabase.',true);
  if (state.busy) return;
  const email = $('email').value.trim();
  const password = $('accountPassword').value;
  if (!email || !password) return toast('Заполните e-mail и пароль аккаунта.',true);
  if (password.length < 8) return toast('Пароль аккаунта должен быть не короче 8 символов.',true);
  busy(true);
  try {
    const path = action === 'signup' ? '/auth/v1/signup' : '/auth/v1/token?grant_type=password';
    const result = await authRequest(path,{email,password});
    $('accountPassword').value = '';
    if (!result.access_token) return toast('Проверьте почту и подтвердите регистрацию. Затем войдите в аккаунт.');
    saveSession(result);
    await loadVaultEnvelope();
    renderWelcome();
    toast('Вход выполнен. Теперь откройте сейф.');
  } catch(e) {toast(niceError(e),true);}
  finally {busy(false);renderWelcome();}
}
async function unlockSubmit(event) {
  event.preventDefault();
  if (state.busy) return;
  if (!crypto?.subtle) return toast('Необходим HTTPS или localhost для Web Crypto.',true);
  const password = $('masterPassword').value;
  const creating = !state.payload;
  if (creating && password.length < 12) return toast('Для мастер-пароля нужно минимум 12 символов (лучше 16+).',true);
  if (creating && password !== $('masterConfirm').value) return toast('Мастер-пароли не совпадают.',true);
  busy(true);
  try {
    if (state.mode === 'cloud') await loadVaultEnvelope(); // check newest ciphertext before unlock
    const isNew = !state.payload;
    if (state.payload && !isValidEnvelope(state.payload)) throw new Error('Данные сейфа повреждены: сначала восстановите копию.');
    if (isNew !== creating) throw new Error('Сейф изменился на сервере. Повторите вход.');
    const salt = isNew ? randomBytes(16) : base64ToBytes(state.payload.salt);
    const iterations = isNew ? KDF_ITERATIONS : state.payload.iterations;
    const key = await deriveKey(password,salt,iterations);
    let items;
    if (isNew) {
      items=[];
      const envelope = await encryptVault(items,key,{salt:bytesToBase64(salt),iterations});
      await persistEnvelope(envelope);
      state.payload=envelope;
    } else {
      items = await decryptVault(state.payload,key);
    }
    state.masterKey=key;
    state.items=items;
    state.lastActivity=Date.now();
    $('masterPassword').value='';$('masterConfirm').value='';
    state.stage='vault';
    $('welcome').classList.add('hidden');
    $('appView').classList.remove('hidden');
    $('syncLabel').textContent=state.mode==='cloud'?'☁ Облако синхронизировано':'◈ Локальный сейф';
    $('refreshButton').classList.toggle('hidden',state.mode==='local');
    state.selectedCategory='Все';state.query='';$('searchInput').value='';
    renderCategories();renderItems();
    toast('Сейф разблокирован');
  } catch(e) {toast(niceError(e),true);}
  finally {busy(false);}
}
function lockVault(showMessage = true) {
  if (state.stage !== 'vault') return;
  state.masterKey=null;state.items=[];state.revealed.clear();state.query='';
  $('entryPassword').value='';$('generatedPassword').textContent='••••••••••••••••';
  document.querySelectorAll('.modal-backdrop').forEach(e=>e.classList.add('hidden'));
  state.stage='master';
  renderWelcome();
  if (showMessage) toast('Сейф заблокирован');
}
async function reloadRemote() {
  if (state.mode !== 'cloud' || state.stage !== 'vault' || state.busy) return;
  busy(true);
  try {
    const remote=await fetchRemote();
    if (remote.version !== state.version) {
      if (!remote.payload || !isValidEnvelope(remote.payload)) throw new Error('Удалённый сейф имеет неверный формат.');
      const items=await decryptVault(remote.payload,state.masterKey);
      state.payload=remote.payload;state.version=Number(remote.version);state.items=items;
      renderItems();
      toast('Обновления получены из облака');
    } else toast('Все записи синхронизированы');
  } catch(e) {
    toast(niceError(e),true);
    if (/Неправильный мастер-пароль|повреждённые данные/.test(String(e.message))) lockVault(false);
  } finally {busy(false);}
}
function esc(s) {return String(s ?? '').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function iconSvg(name) {
  const all = {
    all:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    star:'<path d="m12 2 3.1 6.4 7.1 1-5.1 5 1.2 7.1L12 18.1l-6.3 3.4 1.2-7.1-5.1-5 7.1-1z"/>',
    people:'<circle cx="9" cy="8" r="3"/><path d="M3 20v-2a6 6 0 0 1 12 0v2"/><path d="M16 5a3 3 0 0 1 0 6M17 15a5 5 0 0 1 4 5"/>',
    mail:'<rect x="2" y="5" width="20" height="15" rx="2"/><path d="m3 7 9 7 9-7"/>',
    work:'<rect x="3" y="8" width="18" height="13" rx="2"/><path d="M8 8V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v3M3 13h18"/>',
    money:'<rect x="2" y="5" width="20" height="15" rx="3"/><path d="M2 10h20M6 15h5"/>',
    play:'<rect x="3" y="3" width="18" height="18" rx="5"/><path d="m10 8 6 4-6 4z"/>',
    dots:'<circle cx="5" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="19" cy="12" r="2"/>',
    copy:'<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
    eye:'<path d="M2 12s3.7-6 10-6 10 6 10 6-3.7 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    pencil:'<path d="m3 17 1 4 4-1L20 8a3 3 0 0 0-4-4L4 16Z"/>',
    trash:'<path d="M4 7h16M10 4h4M6 7l1 14h10l1-14M10 11v6m4-6v6"/>',
    link:'<path d="M10 5H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5M13 3h8v8M21 3l-10 10"/>'
  };
  return `<svg viewBox="0 0 24 24" aria-hidden="true">${all[name]}</svg>`;
}
function renderCategories() {
  const icons=['all','star','people','mail','work','money','play','dots'];
  $('categories').innerHTML=CATEGORY_NAMES.map((c,i)=>{
    const count=c==='Все'?state.items.length:c==='Избранное'?state.items.filter(x=>x.favorite).length:state.items.filter(x=>x.category===c).length;
    return `<button type="button" class="category-button ${state.selectedCategory===c?'active':''}" data-category="${esc(c)}" aria-pressed="${state.selectedCategory===c}"><span class="category-svg">${iconSvg(icons[i])}</span><span>${esc(c)}</span><span class="count">${count}</span></button>`;
  }).join('');
}
function brandStyle(name) {
  const n=name.toLowerCase();
  const match=[['google','G','c-google'],['gmail','G','c-google'],['github','GH','c-github'],['telegram','➤','c-telegram'],['netflix','N','c-netflix'],['discord','◈','c-discord'],['tinkoff','T','c-tinkoff']].find(([term])=>n.includes(term));
  if(match) return {glyph:match[1],cls:match[2]};
  const colors=['#2b68c3','#5a58ac','#3683ad','#355cb1','#367d88','#7557bd'];
  let hash=0;for(let i=0;i<n.length;i++)hash=((hash<<5)-hash+n.charCodeAt(i))|0;
  return {glyph:Array.from(name.trim()).slice(0,2).join('').toUpperCase() || '●',color:colors[Math.abs(hash)%colors.length],cls:''};
}
function safeWebsite(input) {
  if(!input)return null;
  try{const u=new URL(input);return ['https:','http:'].includes(u.protocol)?u.href:null;}catch{return null;}
}
function renderItems() {
  if(state.stage!=='vault')return;
  renderCategories();
  const category=state.selectedCategory;
  const query=state.query.toLocaleLowerCase('ru').trim();
  const items=state.items.filter(x=>(category==='Все'||(category==='Избранное'&&x.favorite)||x.category===category)
    &&(!query||[x.name,x.login,x.url,x.category].some(v=>v.toLocaleLowerCase('ru').includes(query))))
    .sort((a,b)=>Number(b.favorite)-Number(a.favorite)||a.name.localeCompare(b.name,'ru'));
  $('entriesStat').textContent=String(state.items.length);
  $('listTitle').textContent=category==='Все'?'Мои пароли':category;
  $('listSubtitle').textContent=`${items.length} ${items.length===1?'запись':items.length>=2&&items.length<=4?'записи':'записей'} в этом разделе`;
  $('emptyState').classList.toggle('hidden',items.length!==0);
  $('entries').classList.toggle('hidden',items.length===0);
  $('emptyAddButton').classList.toggle('hidden',Boolean(query));
  $('emptyText').textContent=query?'По этому запросу ничего не найдено.':'Добавьте первый пароль — он будет надёжно зашифрован.';
  $('entries').innerHTML=items.map(x=>{
    const brand=brandStyle(x.name);
    const revealed=state.revealed.has(x.id);
    const site=safeWebsite(x.url);
    return `<article class="entry"><div class="entry-leading"><span class="service-icon ${brand.cls}" ${brand.color?`style="background:${brand.color}"`:''}>${esc(brand.glyph)}</span><div style="min-width:0"><div class="entry-title">${esc(x.name)}</div><div class="entry-subtitle">${esc(x.login || x.url || 'Без логина')}</div><span class="entry-category">${esc(x.category)}</span></div></div><div class="entry-secret ${revealed?'revealed':''}">${revealed?esc(x.password):'••••••••••'}</div><div class="entry-actions"><button type="button" class="entry-action ${x.favorite?'favorited':''}" data-action="favorite" data-id="${esc(x.id)}" aria-label="${x.favorite?'Удалить из избранного':'В избранное'}" title="Избранное">${iconSvg('star')}</button><button type="button" class="entry-action" data-action="copy" data-id="${esc(x.id)}" aria-label="Копировать пароль" title="Копировать пароль">${iconSvg('copy')}</button><button type="button" class="entry-action" data-action="reveal" data-id="${esc(x.id)}" aria-label="${revealed?'Скрыть':'Показать'} пароль" title="Показать / скрыть">${iconSvg('eye')}</button>${site?`<button type="button" class="entry-action open-link" data-action="open" data-id="${esc(x.id)}" aria-label="Открыть сайт" title="Открыть сайт">${iconSvg('link')}</button>`:''}<button type="button" class="entry-action" data-action="edit" data-id="${esc(x.id)}" aria-label="Редактировать" title="Редактировать">${iconSvg('pencil')}</button><button type="button" class="entry-action" data-action="delete" data-id="${esc(x.id)}" aria-label="Удалить" title="Удалить">${iconSvg('trash')}</button></div></article>`;
  }).join('');
}
function showModal(id) {$ (id).classList.remove('hidden');}
function hideModal(id) {$(id).classList.add('hidden');if(id==='entryModal'){$('entryPassword').type='password';}}
function openEntry(item=null) {
  state.editingId=item?.id||null;
  $('entryModalTitle').textContent=item?'Редактирование записи':'Новый пароль';
  $('entryId').value=item?.id||'';
  $('entryName').value=item?.name||'';
  $('entryLogin').value=item?.login||'';
  $('entryPassword').value=item?.password||'';
  $('entryCategory').value=item?.category||'Работа';
  $('entryUrl').value=item?.url||'';
  $('entryNote').value=item?.note||'';
  $('entryPassword').type='password';
  showModal('entryModal');
  $('entryName').focus();
}
async function onEntryAction(event) {
  const button=event.target.closest('button[data-action]');
  if(!button || state.busy)return;
  const {action,id}=button.dataset;
  const item=state.items.find(x=>x.id===id);
  if(!item)return;
  state.lastActivity=Date.now();
  if(action==='copy') return copyText(item.password);
  if(action==='favorite') return void(await persistItems(state.items.map(x=>x.id===id?{...x,favorite:!x.favorite}:x)));
  if(action==='edit')return openEntry(item);
  if(action==='delete'){
    if(!confirm(`Удалить «${item.name}»? Это действие нельзя отменить.`))return;
    if(await persistItems(state.items.filter(x=>x.id!==id)))toast('Запись удалена');
    return;
  }
  if(action==='open') {const url=safeWebsite(item.url);if(url)window.open(url,'_blank','noopener,noreferrer');return;}
  if(action==='reveal'){
    if(state.revealed.has(id))state.revealed.delete(id);
    else{state.revealed.set(id,Date.now()+12000);setTimeout(()=>{if(state.revealed.get(id)<=Date.now()){state.revealed.delete(id);renderItems();}},12500);}
    renderItems();
  }
}
async function saveEntry(event) {
  event.preventDefault();
  if(state.busy)return;
  const name=$('entryName').value.trim();
  const password=$('entryPassword').value;
  if(!name||!password)return toast('Название и пароль обязательны.',true);
  const url=$('entryUrl').value.trim();
  if(url&&!safeWebsite(url))return toast('Адрес сайта должен начинаться с https:// или http://',true);
  const old=state.items.find(x=>x.id===state.editingId);
  const entry={id:old?.id||crypto.randomUUID(),name,login:$('entryLogin').value.trim(),password,
    category:$('entryCategory').value,url,note:$('entryNote').value.trim(),favorite:old?.favorite||false,
    createdAt:old?.createdAt||new Date().toISOString(),updatedAt:new Date().toISOString()};
  const next=old?state.items.map(x=>x.id===old.id?entry:x):[...state.items,entry];
  if(await persistItems(next)){hideModal('entryModal');$('entryForm').reset();toast(old?'Пароль обновлён':'Пароль сохранён');}
}
async function copyText(value) {
  try{
    await navigator.clipboard.writeText(value);
    toast('Пароль скопирован. Буфер обмена может быть виден другим приложениям.');
    // Clear only if clipboard still contains exactly our secret. Clipboard reads may be denied.
    setTimeout(async()=>{try{const current=await navigator.clipboard.readText();if(current===value)await navigator.clipboard.writeText('');}catch{}},20000);
  }catch{toast('Не удалось скопировать. Разрешите доступ к буферу обмена.',true);}
}
function randomIndex(size) {
  const range=0x100000000;
  const max=range-(range%size);
  const buffer=new Uint32Array(1);
  let n;
  do {crypto.getRandomValues(buffer);n=buffer[0];} while(n>=max);
  return n%size;
}
function generatePassword() {
  const sets=[];
  if($('genUpper').checked)sets.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if($('genLower').checked)sets.push('abcdefghijkmnopqrstuvwxyz');
  if($('genDigits').checked)sets.push('23456789');
  if($('genSymbols').checked)sets.push('!@#$%^&*()-_=+?');
  if(!sets.length){toast('Выберите хотя бы один набор символов.',true);return null;}
  const length=Number($('generatorLength').value);
  const alphabet=sets.join('');
  const result=sets.map(set=>set[randomIndex(set.length)]);
  while(result.length<length)result.push(alphabet[randomIndex(alphabet.length)]);
  for(let i=result.length-1;i>0;i--){const j=randomIndex(i+1);[result[i],result[j]]=[result[j],result[i]];}
  const password=result.join('');
  $('generatedPassword').textContent=password;
  return password;
}
function exportBackup() {
  if(!state.payload)return;
  const backup={application:'SecureBox',backupVersion:1,createdAt:new Date().toISOString(),vault:state.payload};
  const blob=new Blob([JSON.stringify(backup,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=`securebox-backup-${new Date().toISOString().slice(0,10)}.json`;
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500);
  toast('Зашифрованная резервная копия сохранена');
}
async function importBackup(file) {
  if(!file||state.busy)return;
  if(file.size>15*1024*1024)return toast('Слишком большой файл резервной копии.',true);
  try {
    const backup=JSON.parse(await file.text());
    if(backup.application!=='SecureBox'||backup.backupVersion!==1||!isValidEnvelope(backup.vault))throw new Error('Это не резервная копия SecureBox или файл повреждён.');
    if(!confirm('ВНИМАНИЕ: импорт ЗАМЕНИТ все текущие записи. Для открытия потребуется мастер-пароль, использованный при создании резервной копии. Продолжить?'))return;
    busy(true);
    await persistEnvelope(backup.vault);
    state.payload=backup.vault;
    toast('Копия импортирована. Откройте сейф мастер-паролем от копии.');
    if(state.stage==='vault')lockVault(false);else renderWelcome();
  }catch(e){toast(niceError(e),true);}
  finally{$('importFile').value='';$('restoreFile').value='';busy(false);}
}
async function signOut() {
  if(state.busy)return;
  if(state.mode==='cloud') {
    sessionStorage.removeItem(SESSION_KEY);
    state.session=null;
  }
  lockVault(false);
  if(state.mode==='cloud'){state.payload=null;state.version=0;}
  renderWelcome();
  toast('Вы вышли из сейфа');
}
function registerListeners() {
  $('localModeButton').addEventListener('click',()=>setMode('local'));
  $('cloudModeButton').addEventListener('click',()=>setMode('cloud'));
  $('cloudForm').addEventListener('submit',e=>{e.preventDefault();accountAction('signin');});
  $('cloudSignUpButton').addEventListener('click',()=>accountAction('signup'));
  $('unlockForm').addEventListener('submit',unlockSubmit);
  $('backToCloud').addEventListener('click',()=>{state.session=null;sessionStorage.removeItem(SESSION_KEY);state.payload=null;state.version=0;renderWelcome();});
  $('searchInput').addEventListener('input',e=>{state.query=e.target.value;renderItems();});
  $('categories').addEventListener('click',e=>{const b=e.target.closest('[data-category]');if(!b)return;state.selectedCategory=b.dataset.category;renderItems();});
  $('addButton').addEventListener('click',()=>openEntry());
  $('emptyAddButton').addEventListener('click',()=>openEntry());
  $('entries').addEventListener('click',onEntryAction);
  $('entryForm').addEventListener('submit',saveEntry);
  $('toggleEntryPassword').addEventListener('click',()=>{$('entryPassword').type=$('entryPassword').type==='password'?'text':'password';});
  $('fillGenerated').addEventListener('click',()=>{const p=generatePassword();if(p)$('entryPassword').value=p;});
  $('generatorButton').addEventListener('click',()=>{generatePassword();showModal('generatorModal');});
  $('generatorLength').addEventListener('input',e=>{$('lengthValue').textContent=e.target.value;generatePassword();});
  ['genUpper','genLower','genDigits','genSymbols'].forEach(id=>$(id).addEventListener('change',generatePassword));
  $('regenerateButton').addEventListener('click',generatePassword);
  $('copyGenerated').addEventListener('click',()=>{const text=$('generatedPassword').textContent;if(text&&!text.includes('•'))copyText(text);});
  $('settingsButton').addEventListener('click',()=>showModal('settingsModal'));
  $('exportButton').addEventListener('click',exportBackup);
  $('importButton').addEventListener('click',()=>$('importFile').click());
  $('importFile').addEventListener('change',e=>importBackup(e.target.files[0]));
  $('restoreAtWelcome').addEventListener('click',()=>$('restoreFile').click());
  $('restoreFile').addEventListener('change',e=>importBackup(e.target.files[0]));
  $('logoutButton').addEventListener('click',signOut);
  $('lockButton').addEventListener('click',()=>lockVault());
  $('refreshButton').addEventListener('click',reloadRemote);
  document.querySelectorAll('[data-close]').forEach(button=>button.addEventListener('click',()=>hideModal(button.dataset.close)));
  document.querySelectorAll('.modal-backdrop').forEach(modal=>modal.addEventListener('click',e=>{if(e.target===modal)hideModal(modal.id);}));
  document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal-backdrop:not(.hidden)').forEach(modal=>hideModal(modal.id));});
  ['pointerdown','keydown','touchstart'].forEach(event=>document.addEventListener(event,()=>{if(state.stage==='vault')state.lastActivity=Date.now();},{passive:true}));
  document.addEventListener('visibilitychange',()=>{
    if(!document.hidden&&state.stage==='vault'){
      if(Date.now()-state.lastActivity>=AUTO_LOCK_MS)lockVault();
      else if(state.mode==='cloud'&&navigator.onLine)reloadRemote();
    }
  });
  window.addEventListener('storage',e=>{if(state.stage==='vault'&&state.mode==='local'&&e.key===STORAGE_KEY)lockVault(true);});
  setInterval(()=>{if(state.stage==='vault'&&Date.now()-state.lastActivity>=AUTO_LOCK_MS)lockVault();},15000);
}
async function init() {
  registerListeners();
  if(!crypto?.subtle)toast('Для работы шифрования откройте приложение через HTTPS (например, GitHub Pages).',true);
  if(state.mode==='local')localOnlyLoad();
  if(state.mode==='cloud') {
    const stored=safeJSON(sessionStorage.getItem(SESSION_KEY));
    if(stored?.refresh_token){
      try{state.session=stored;await refreshSession();await loadVaultEnvelope();}
      catch(e){state.session=null;sessionStorage.removeItem(SESSION_KEY);toast('Облачная сессия завершена. Войдите ещё раз.');}
    }
  }
  renderWelcome();
}
init();

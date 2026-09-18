# affiliate_market_server.py
# One-file Affiliate Market Pro: Backend + SQLite Database + Frontend
# Run: python affiliate_market_server.py
# Open: http://127.0.0.1:5000
#
# Optional Telegram Mini App:
# Set BOT_TOKEN as an environment variable, then configure this HTTPS URL
# as the Mini App URL in BotFather. Telegram initData validation is included.

import os, json, hmac, hashlib, sqlite3, secrets, time
from functools import wraps
from urllib.parse import parse_qsl

from flask import Flask, request, jsonify, session, g, render_template_string, redirect

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", secrets.token_hex(32))
DB = os.environ.get("DATABASE_FILE", "affiliate_market.db")
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")

CATEGORIES = {
 "Cosmetics":["Makeup","Skincare","Hair Care","Perfume","Body Care","Nail Care"],
 "Electronics":["Phones","Laptops","Headphones","Smart Watches","TV","Accessories"],
 "Home & Kitchen":["Furniture","Kitchen","Decoration","Cleaning","Lighting","Storage"],
 "Fashion":["Men","Women","Shoes","Bags","Watches","Accessories"],
 "Grocery":["Food","Beverages","Household","Personal Care"],
 "Kids":["Baby","Toys","Kids Fashion","School"],
 "Sports":["Fitness","Sportswear","Equipment","Outdoor"],
 "Books":["Books","Education","Stationery"],
 "Tools":["Hand Tools","Power Tools","Hardware"]
}

def conn():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db=g.pop("db",None)
    if db: db.close()

def init_db():
    db=sqlite3.connect(DB)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_id TEXT UNIQUE,
      name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Customer',
      pin_hash TEXT, blocked INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS categories(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS subcategories(
      id INTEGER PRIMARY KEY AUTOINCREMENT, category_id INTEGER NOT NULL,
      name TEXT NOT NULL, UNIQUE(category_id,name),
      FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS products(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT,
      price REAL NOT NULL, old_price REAL DEFAULT 0, category_id INTEGER,
      subcategory_id INTEGER, brand TEXT, sku TEXT, image TEXT,
      affiliate_link TEXT, affiliate_network TEXT, tags TEXT,
      active INTEGER DEFAULT 1, featured INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL,
      FOREIGN KEY(subcategory_id) REFERENCES subcategories(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS favorites(
      user_id INTEGER, product_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(user_id,product_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS affiliate_clicks(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, product_id INTEGER,
      converted INTEGER DEFAULT 0, commission REAL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY, value TEXT
    );
    """)
    # Seed owner only once. The initial PIN is 1234 and must be changed in Settings.
    if db.execute("SELECT COUNT(*) FROM users WHERE role='Owner'").fetchone()[0] == 0:
        ph=hash_pin("1234")
        db.execute("INSERT INTO users(name,role,pin_hash) VALUES(?,?,?)",("Owner","Owner",ph))
    if db.execute("SELECT COUNT(*) FROM categories").fetchone()[0] == 0:
        for cat,subs in CATEGORIES.items():
            cur=db.execute("INSERT INTO categories(name) VALUES(?)",(cat,))
            cid=cur.lastrowid
            db.executemany("INSERT INTO subcategories(category_id,name) VALUES(?,?)",[(cid,x) for x in subs])
    for k,v in {"store_name":"Affiliate Market Pro","currency":"ብር"}.items():
        db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",(k,v))
    db.commit(); db.close()

def hash_pin(pin):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), app.secret_key.encode(), 180000).hex()

def check_pin(pin,hashed):
    return hmac.compare_digest(hash_pin(pin),hashed or "")

def current_user():
    uid=session.get("uid")
    if not uid:return None
    return conn().execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()

def owner_required(fn):
    @wraps(fn)
    def w(*a,**kw):
        u=current_user()
        if not u or u["role"]!="Owner": return jsonify(error="Owner access required"),403
        return fn(*a,**kw)
    return w

def customer_required(fn):
    @wraps(fn)
    def w(*a,**kw):
        u=current_user()
        if not u or u["blocked"]: return jsonify(error="Login required"),401
        return fn(*a,**kw)
    return w

def telegram_user(init_data):
    if not BOT_TOKEN or not init_data: return None
    try:
        pairs=dict(parse_qsl(init_data,keep_blank_values=True))
        received=pairs.pop("hash",None)
        if not received:return None
        data_check="\n".join(f"{k}={pairs[k]}" for k in sorted(pairs))
        secret=hmac.new(b"WebAppData",BOT_TOKEN.encode(),hashlib.sha256).digest()
        calc=hmac.new(secret,data_check.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc,received):return None
        auth=int(pairs.get("auth_date","0"))
        if time.time()-auth>86400:return None
        return json.loads(pairs.get("user","{}"))
    except Exception:return None

@app.route("/")
def index():
    return render_template_string(FRONTEND)

@app.post("/api/login")
def login():
    data=request.json or {}; db=conn()
    u=db.execute("SELECT * FROM users WHERE name=?",(data.get("name",""),)).fetchone()
    if not u or u["blocked"] or not check_pin(data.get("pin",""),u["pin_hash"]):
        return jsonify(error="Invalid login"),401
    session["uid"]=u["id"]
    return jsonify(user=dict(u))

@app.post("/api/register")
def register():
    data=request.json or {}; name=data.get("name","").strip(); pin=data.get("pin","")
    if not name or not pin.isdigit() or not 4<=len(pin)<=6:return jsonify(error="Name and 4-6 digit PIN required"),400
    db=conn()
    try:
        cur=db.execute("INSERT INTO users(name,role,pin_hash) VALUES(?,?,?)",(name,"Customer",hash_pin(pin)))
        db.commit(); session["uid"]=cur.lastrowid
        return jsonify(ok=True,user=dict(db.execute("SELECT * FROM users WHERE id=?",(cur.lastrowid,)).fetchone()))
    except sqlite3.IntegrityError:return jsonify(error="Name already exists"),409

@app.post("/api/telegram/login")
def telegram_login():
    tu=telegram_user((request.json or {}).get("initData",""))
    if not tu:return jsonify(error="Telegram authentication failed"),401
    db=conn(); tid=str(tu.get("id")); name=tu.get("first_name","Telegram User")
    u=db.execute("SELECT * FROM users WHERE telegram_id=?",(tid,)).fetchone()
    if not u:
        cur=db.execute("INSERT INTO users(telegram_id,name,role) VALUES(?,?,?)",(tid,name,"Customer"))
        db.commit(); u=db.execute("SELECT * FROM users WHERE id=?",(cur.lastrowid,)).fetchone()
    if u["blocked"]:return jsonify(error="Account blocked"),403
    session["uid"]=u["id"];return jsonify(user=dict(u))

@app.post("/api/logout")
def logout(): session.clear(); return jsonify(ok=True)

@app.get("/api/me")
def me():
    u=current_user(); return jsonify(user=dict(u) if u else None)

@app.get("/api/products")
def products():
    db=conn(); rows=db.execute("""SELECT p.*,c.name category,s.name subcategory
      FROM products p LEFT JOIN categories c ON c.id=p.category_id
      LEFT JOIN subcategories s ON s.id=p.subcategory_id
      WHERE p.active=1 ORDER BY p.id DESC""").fetchall()
    return jsonify(products=[dict(x) for x in rows])

@app.get("/api/categories")
def cats():
    db=conn(); cs=[]
    for c in db.execute("SELECT * FROM categories ORDER BY name"):
        subs=[dict(x) for x in db.execute("SELECT * FROM subcategories WHERE category_id=? ORDER BY name",(c["id"],))]
        cs.append({"id":c["id"],"name":c["name"],"subs":subs})
    return jsonify(categories=cs)

@app.post("/api/favorites/<int:pid>")
@customer_required
def favorite(pid):
    db=conn();uid=current_user()["id"]
    row=db.execute("SELECT 1 FROM favorites WHERE user_id=? AND product_id=?",(uid,pid)).fetchone()
    if row: db.execute("DELETE FROM favorites WHERE user_id=? AND product_id=?",(uid,pid)); state=False
    else: db.execute("INSERT OR IGNORE INTO favorites(user_id,product_id) VALUES(?,?)",(uid,pid)); state=True
    db.commit();return jsonify(favorite=state)

@app.get("/api/favorites")
@customer_required
def favorites():
    uid=current_user()["id"]; rows=conn().execute("""SELECT p.*,c.name category,s.name subcategory FROM favorites f
      JOIN products p ON p.id=f.product_id LEFT JOIN categories c ON c.id=p.category_id
      LEFT JOIN subcategories s ON s.id=p.subcategory_id WHERE f.user_id=?""",(uid,)).fetchall()
    return jsonify(products=[dict(x) for x in rows])

@app.post("/api/click/<int:pid>")
@customer_required
def click(pid):
    db=conn();uid=current_user()["id"]
    p=db.execute("SELECT * FROM products WHERE id=? AND active=1",(pid,)).fetchone()
    if not p:return jsonify(error="Product not found"),404
    db.execute("INSERT INTO affiliate_clicks(user_id,product_id) VALUES(?,?)",(uid,pid));db.commit()
    return jsonify(url=p["affiliate_link"] or "")

# ---------- OWNER API ----------
@app.post("/api/owner/products")
@owner_required
def add_product():
    d=request.json or {};db=conn()
    cur=db.execute("""INSERT INTO products(name,description,price,old_price,category_id,subcategory_id,brand,sku,image,affiliate_link,affiliate_network,tags,active,featured)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(d.get("name"),d.get("description"),d.get("price",0),d.get("old_price",0),d.get("category_id"),d.get("subcategory_id"),d.get("brand"),d.get("sku"),d.get("image"),d.get("affiliate_link"),d.get("affiliate_network"),d.get("tags"),int(d.get("active",1)),int(d.get("featured",0))))
    db.commit();return jsonify(id=cur.lastrowid)

@app.put("/api/owner/products/<int:pid>")
@owner_required
def edit_product(pid):
    d=request.json or {};db=conn()
    db.execute("""UPDATE products SET name=?,description=?,price=?,old_price=?,category_id=?,subcategory_id=?,brand=?,sku=?,image=?,affiliate_link=?,affiliate_network=?,tags=?,active=?,featured=? WHERE id=?""",
      (d.get("name"),d.get("description"),d.get("price",0),d.get("old_price",0),d.get("category_id"),d.get("subcategory_id"),d.get("brand"),d.get("sku"),d.get("image"),d.get("affiliate_link"),d.get("affiliate_network"),d.get("tags"),int(d.get("active",1)),int(d.get("featured",0)),pid))
    db.commit();return jsonify(ok=True)

@app.delete("/api/owner/products/<int:pid>")
@owner_required
def del_product(pid):
    db=conn();db.execute("DELETE FROM products WHERE id=?",(pid,));db.commit();return jsonify(ok=True)

@app.get("/api/owner/products")
@owner_required
def owner_products():
    db=conn(); rows=db.execute("""SELECT p.*,c.name category,s.name subcategory FROM products p
      LEFT JOIN categories c ON c.id=p.category_id LEFT JOIN subcategories s ON s.id=p.subcategory_id ORDER BY p.id DESC""").fetchall()
    return jsonify(products=[dict(x) for x in rows])

@app.post("/api/owner/categories")
@owner_required
def add_cat():
    d=request.json or {};db=conn()
    try:
        cur=db.execute("INSERT INTO categories(name) VALUES(?)",(d["name"],));cid=cur.lastrowid
        for x in d.get("subs",[]):db.execute("INSERT OR IGNORE INTO subcategories(category_id,name) VALUES(?,?)",(cid,x))
        db.commit();return jsonify(id=cid)
    except sqlite3.IntegrityError:return jsonify(error="Category exists"),409

@app.put("/api/owner/categories/<int:cid>")
@owner_required
def edit_cat(cid):
    d=request.json or {};db=conn();db.execute("UPDATE categories SET name=? WHERE id=?",(d["name"],cid))
    db.execute("DELETE FROM subcategories WHERE category_id=?",(cid,))
    for x in d.get("subs",[]):db.execute("INSERT OR IGNORE INTO subcategories(category_id,name) VALUES(?,?)",(cid,x))
    db.commit();return jsonify(ok=True)

@app.delete("/api/owner/categories/<int:cid>")
@owner_required
def del_cat(cid):
    db=conn();db.execute("DELETE FROM categories WHERE id=?",(cid,));db.commit();return jsonify(ok=True)

@app.get("/api/owner/users")
@owner_required
def owner_users():
    return jsonify(users=[dict(x) for x in conn().execute("SELECT id,telegram_id,name,role,blocked,created_at FROM users ORDER BY id DESC")])

@app.put("/api/owner/users/<int:uid>")
@owner_required
def owner_user(uid):
    d=request.json or {};db=conn()
    if "pin" in d and d["pin"]: db.execute("UPDATE users SET pin_hash=? WHERE id=?",(hash_pin(d["pin"]),uid))
    if "name" in d: db.execute("UPDATE users SET name=? WHERE id=?",(d["name"],uid))
    if "blocked" in d: db.execute("UPDATE users SET blocked=? WHERE id=?",(int(d["blocked"]),uid))
    db.commit();return jsonify(ok=True)

@app.post("/api/owner/pin")
@owner_required
def owner_pin():
    d=request.json or {};u=current_user()
    if not check_pin(d.get("current",""),u["pin_hash"]):return jsonify(error="Current PIN incorrect"),400
    new=d.get("new","")
    if not new.isdigit() or not 4<=len(new)<=6 or new!=d.get("confirm",""):return jsonify(error="New PIN invalid"),400
    db=conn();db.execute("UPDATE users SET pin_hash=? WHERE id=?",(hash_pin(new),u["id"]));db.commit();return jsonify(ok=True)

@app.get("/api/owner/analytics")
@owner_required
def analytics():
    db=conn()
    total=db.execute("SELECT COUNT(*) n FROM affiliate_clicks").fetchone()["n"]
    conv=db.execute("SELECT COUNT(*) n FROM affiliate_clicks WHERE converted=1").fetchone()["n"]
    com=db.execute("SELECT COALESCE(SUM(commission),0) n FROM affiliate_clicks").fetchone()["n"]
    rows=db.execute("""SELECT p.name,COUNT(a.id) clicks,SUM(a.converted) conversions,COALESCE(SUM(a.commission),0) commission
      FROM products p LEFT JOIN affiliate_clicks a ON a.product_id=p.id GROUP BY p.id ORDER BY clicks DESC""").fetchall()
    return jsonify(total_clicks=total,conversions=conv,commission=com,products=[dict(x) for x in rows])

@app.get("/api/owner/settings")
@owner_required
def get_settings():
    return jsonify(settings={r["key"]:r["value"] for r in conn().execute("SELECT * FROM settings")})

@app.put("/api/owner/settings")
@owner_required
def set_settings():
    db=conn()
    for k,v in (request.json or {}).items():db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",(k,str(v)))
    db.commit();return jsonify(ok=True)

FRONTEND = r"""
<!doctype html><html lang="am"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Affiliate Market Pro</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,"Noto Sans Ethiopic",sans-serif;background:#f5f7fb;color:#172033}
button,input,select,textarea{font:inherit}button{border:0;border-radius:10px;padding:10px 14px;background:#2563eb;color:white;font-weight:700;cursor:pointer}
input,select,textarea{padding:10px;border:1px solid #ddd;border-radius:10px;width:100%}.hidden{display:none!important}.card{background:white;border:1px solid #e5e7eb;border-radius:16px;padding:16px}.login{min-height:100vh;display:grid;place-items:center;padding:20px;background:#eaf2ff}.loginbox{width:min(420px,100%);padding:25px;background:white;border-radius:20px;box-shadow:0 15px 50px #0002}.field{margin:10px 0}.err{color:#dc2626;min-height:20px}
.app{display:flex;min-height:100vh}.side{width:240px;background:#111827;color:white;padding:16px;position:fixed;inset:0 auto 0 0}.side button{width:100%;text-align:left;margin:4px 0;background:transparent}.side button:hover{background:#2563eb}.main{margin-left:240px;padding:20px;flex:1}.top{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat b{font-size:25px;display:block;margin-top:7px}.section{margin-top:18px}.products{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.prod img{width:100%;height:180px;object-fit:cover;border-radius:12px}.price{font-size:20px;font-weight:bold}.old{text-decoration:line-through;color:#999;font-size:12px}.tag{display:inline-block;padding:4px 8px;background:#eef2ff;border-radius:999px;font-size:12px;margin:3px}.filters{display:grid;grid-template-columns:2fr 1fr 1fr;gap:10px;margin:15px 0}.hero{padding:25px;border-radius:20px;background:linear-gradient(135deg,#2563eb,#7c3aed);color:white}.customer{max-width:1200px;margin:auto;padding:15px}.nav{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:12px 0;position:sticky;top:0;background:#f5f7fb;z-index:3}.nav button{background:white;color:#172033}.modal{position:fixed;inset:0;background:#0008;display:grid;place-items:center;padding:15px;z-index:10}.modalbox{background:white;padding:20px;border-radius:18px;width:min(700px,100%);max-height:90vh;overflow:auto}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.span{grid-column:span 2}
@media(max-width:900px){.grid,.products{grid-template-columns:repeat(2,1fr)}}@media(max-width:650px){.side{width:64px}.side button{font-size:0;text-align:center}.main{margin-left:64px;padding:12px}.grid,.products,.formgrid,.filters{grid-template-columns:1fr}.span{grid-column:auto}}
</style></head><body>
<div id="login" class="login"><div class="loginbox"><div style="font-size:40px;text-align:center">🛍️</div><h2 style="text-align:center">Affiliate Market Pro</h2>
<p style="text-align:center;color:#667085">Owner እና Customer የተለያዩ መዳረሻዎች</p>
<div class="field"><label>User</label><select id="lname"></select></div><div class="field"><label>PIN</label><input id="lpin" type="password" inputmode="numeric"></div><div id="err" class="err"></div>
<button style="width:100%" onclick="login()">Login</button><button style="width:100%;margin-top:8px;background:#eef2ff;color:#1d4ed8" onclick="register()">📝 Create Customer Account</button>
<small style="display:block;text-align:center;color:#667085;margin-top:10px">Demo Owner መጀመሪያ PIN: 1234 — ከገቡ በኋላ ይቀይሩት</small></div></div>

<div id="owner" class="app hidden"><aside class="side"><h3>🛍️ Affiliate Pro</h3>
<button onclick="op('dashboard')">📊 Dashboard</button><button onclick="op('products')">🛍️ Products</button><button onclick="op('categories')">📂 Categories</button><button onclick="op('users')">👥 Users</button><button onclick="op('analytics')">📈 Analytics</button><button onclick="op('settings')">⚙️ Settings</button><button onclick="logout()">🔒 Lock</button></aside>
<main class="main"><div class="top"><div><h2 id="ot">Dashboard</h2><small>Owner / Admin</small></div><b id="on"></b></div><div id="oc"></div></main></div>

<div id="customer" class="hidden customer"><div class="nav"><b>🛍️ Affiliate Market</b><div><button onclick="cp('home')">🏠</button><button onclick="cp('products')">🛍️ Products</button><button onclick="cp('favorites')">❤️</button><button onclick="logout()">🚪</button></div></div><div id="cc"></div></div>
<div id="modal" class="modal hidden"><div class="modalbox"><div style="display:flex;justify-content:space-between"><h3 id="mt"></h3><button onclick="closeM()">✕</button></div><div id="mb"></div></div></div>
<script>
let ME=null, PRODUCTS=[], CATS=[];
const $=x=>document.getElementById(x);
async function api(url,opt={}){let r=await fetch(url,{headers:{'Content-Type':'application/json'},...opt});let d=await r.json();if(!r.ok)throw Error(d.error||'Error');return d}
async function start(){let m=await api('/api/me');if(m.user){ME=m.user;show()}else await loadLogin()}
async function loadLogin(){let d=await api('/api/owner/users').catch(()=>null);if(d) fillUsers(d.users);else{$('lname').innerHTML='<option>Loading...</option>'; let fake=await api('/api/me');}}
async function fillUsers(users){$('lname').innerHTML=users.filter(u=>!u.blocked).map(u=>`<option value="${esc(u.name)}">${esc(u.name)} — ${u.role}</option>`).join('')}
async function login(){try{let d=await api('/api/login',{method:'POST',body:JSON.stringify({name:$('lname').value,pin:$('lpin').value})});ME=d.user;show()}catch(e){$('err').textContent=e.message}}
async function register(){openM('Create Customer Account',`<div class="field"><label>Name</label><input id="rn"></div><div class="field"><label>PIN (4–6 digits)</label><input id="rp" type="password"></div><div class="field"><label>Confirm PIN</label><input id="rp2" type="password"></div><button onclick="doReg()">Create Account</button>`)}
async function doReg(){try{let d=await api('/api/register',{method:'POST',body:JSON.stringify({name:$('rn').value,pin:$('rp').value,confirm:$('rp2').value})});ME=d.user;closeM();show()}catch(e){alert(e.message)}}
function show(){ $('login').classList.add('hidden');if(ME.role==='Owner'){ $('owner').classList.remove('hidden');$('customer').classList.add('hidden');$('on').textContent='👑 '+ME.name;op('dashboard')}else{$('customer').classList.remove('hidden');$('owner').classList.add('hidden');cp('home')}}
async function logout(){await api('/api/logout',{method:'POST'});ME=null;$('owner').classList.add('hidden');$('customer').classList.add('hidden');$('login').classList.remove('hidden');await loadLogin()}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function money(n){return Number(n||0).toLocaleString()+' ብር'}
async function op(p){$('ot').textContent=p[0].toUpperCase()+p.slice(1);({dashboard:od,products:oprod,categories:ocat,users:ousers,analytics:oana,settings:oset}[p])()}
async function od(){let [ps,u,a]=await Promise.all([api('/api/owner/products'),api('/api/owner/users'),api('/api/owner/analytics')]);$('oc').innerHTML=`<div class="grid">${st('Products',ps.products.length)}${st('Active',ps.products.filter(x=>x.active).length)}${st('Users',u.users.length)}${st('Clicks',a.total_clicks)}${st('Conversions',a.conversions)}${st('Commission',money(a.commission))}</div><div class="card section"><button onclick="newProd()">➕ Add Product</button> <button onclick="newCat()">📂 Add Category</button></div><div class="section"><h3>Featured</h3><div class="products">${ps.products.filter(x=>x.featured&&x.active).slice(0,4).map(pc).join('')}</div></div>`}
function st(a,b){return `<div class="card stat">${a}<b>${b}</b></div>`}
async function oprod(){let d=await api('/api/owner/products');PRODUCTS=d.products;$('oc').innerHTML=`<div style="text-align:right"><button onclick="newProd()">➕ Add Product</button></div><div class="filters"><input id="q" placeholder="Search..." oninput="filterP()"><select id="fc" onchange="filterP()"><option value="">All categories</option>${CATS.map(c=>`<option>${esc(c.name)}</option>`).join('')}</select><select id="fs" onchange="filterP()"><option value="">All</option><option value="1">Active</option><option value="0">Inactive</option></select></div><div id="plist" class="products"></div>`;filterP()}
function filterP(){let q=($('q')?.value||'').toLowerCase(),c=$('fc')?.value||'',s=$('fs')?.value||'';let a=PRODUCTS.filter(p=>(p.name+' '+(p.tags||'')).toLowerCase().includes(q)&&(!c||p.category===c)&&(!s||String(p.active?1:0)===s));$('plist').innerHTML=a.map(p=>pc(p)+`<div class="card"><button onclick="editP(${p.id})">✏️ Edit</button> <button style="background:#dc2626" onclick="delP(${p.id})">🗑️ Delete</button></div>`).join('')||'<p>No products</p>'}
function pc(p){return `<div class="card prod"><img src="${esc(p.image||'')}" onerror="this.style.display='none'"><span class="tag">${esc(p.category||'')}</span><span class="tag">${esc(p.subcategory||'')}</span><h3>${esc(p.name)}</h3><p>${esc(p.description||'')}</p><div class="price">${money(p.price)} ${p.old_price?`<span class="old">${money(p.old_price)}</span>`:''}</div></div>`}
async function ocat(){let d=await api('/api/categories');CATS=d.categories;$('oc').innerHTML=`<div style="text-align:right"><button onclick="newCat()">➕ Add Category</button></div><div class="grid section">${CATS.map(c=>`<div class="card"><h3>📂 ${esc(c.name)}</h3>${c.subs.map(s=>`<span class="tag">${esc(s.name)}</span>`).join('')}<p><button onclick="editCat(${c.id})">✏️ Edit</button> <button style="background:#dc2626" onclick="delCat(${c.id})">🗑️ Delete</button></p></div>`).join('')}</div>`}
async function ousers(){let d=await api('/api/owner/users');$('oc').innerHTML=`<div class="card"><table style="width:100%"><tr><th>Name</th><th>Role</th><th>Status</th><th></th></tr>${d.users.map(u=>`<tr><td>${esc(u.name)}</td><td>${u.role}</td><td>${u.blocked?'Blocked':'Active'}</td><td>${u.role==='Customer'?`<button onclick="toggleU(${u.id},${u.blocked?0:1})">${u.blocked?'Unblock':'Block'}</button>`:''}</td></tr>`).join('')}</table></div>`}
async function toggleU(id,b){await api('/api/owner/users/'+id,{method:'PUT',body:JSON.stringify({blocked:b})});ousers()}
async function oana(){let d=await api('/api/owner/analytics');$('oc').innerHTML=`<div class="grid">${st('Clicks',d.total_clicks)}${st('Conversions',d.conversions)}${st('Commission',money(d.commission))}</div><div class="card section"><table style="width:100%"><tr><th>Product</th><th>Clicks</th><th>Conversions</th><th>Commission</th></tr>${d.products.map(x=>`<tr><td>${esc(x.name)}</td><td>${x.clicks}</td><td>${x.conversions||0}</td><td>${money(x.commission)}</td></tr>`).join('')}</table></div>`}
async function oset(){let d=await api('/api/owner/settings');$('oc').innerHTML=`<div class="card"><h3>⚙️ Settings</h3><div class="field"><label>Store Name</label><input id="sn" value="${esc(d.settings.store_name||'')}"></div><div class="field"><label>Currency</label><input id="cu" value="${esc(d.settings.currency||'ብር')}"></div><button onclick="saveSet()">Save</button></div><div class="card section"><h3>🔐 Security</h3><button onclick="pinModal()">Change Owner PIN</button></div>`}
async function saveSet(){await api('/api/owner/settings',{method:'PUT',body:JSON.stringify({store_name:$('sn').value,currency:$('cu').value})});alert('Saved')}
function pinModal(){openM('Change Owner PIN',`<input id="po" placeholder="Current PIN" type="password"><input id="pn" placeholder="New PIN" type="password" style="margin-top:8px"><input id="pc" placeholder="Confirm New PIN" type="password" style="margin-top:8px"><button style="margin-top:8px" onclick="changePin()">Save</button>`)}
async function changePin(){try{await api('/api/owner/pin',{method:'POST',body:JSON.stringify({current:$('po').value,new:$('pn').value,confirm:$('pc').value})});closeM();alert('Owner PIN changed')}catch(e){alert(e.message)}}
async function newProd(){let d=await api('/api/categories');CATS=d.categories;openM('Add Product',prodForm())}
function prodForm(p={}){return `<div class="formgrid"><div><label>Name</label><input id="pn" value="${esc(p.name||'')}"></div><div><label>Price</label><input id="pp" type="number" value="${p.price||''}"></div><div><label>Old Price</label><input id="po" type="number" value="${p.old_price||''}"></div><div><label>Category</label><select id="pcat">${CATS.map(c=>`<option value="${c.id}" ${p.category_id==c.id?'selected':''}>${esc(c.name)}</option>`).join('')}</select></div><div><label>Subcategory</label><select id="psub"></select></div><div><label>Brand</label><input id="pb" value="${esc(p.brand||'')}"></div><div><label>Image URL</label><input id="pi" value="${esc(p.image||'')}"></div><div><label>Affiliate Link</label><input id="pa" value="${esc(p.affiliate_link||'')}"></div><div><label>Network</label><input id="pnet" value="${esc(p.affiliate_network||'')}"></div><div><label>Tags</label><input id="pt" value="${esc(p.tags||'')}"></div><div class="span"><label>Description</label><textarea id="pd">${esc(p.description||'')}</textarea></div><div class="span"><label><input id="act" type="checkbox" ${p.active!==0?'checked':''}> Active</label> <label><input id="feat" type="checkbox" ${p.featured?'checked':''}> Featured</label></div><div class="span"><button onclick="saveP(${p.id||0})">💾 Save</button></div></div>`}
function fillSub(cid,selected){let c=CATS.find(x=>x.id==cid);$('psub').innerHTML=(c?.subs||[]).map(s=>`<option value="${s.id}" ${selected==s.id?'selected':''}>${esc(s.name)}</option>`).join('')}
async function editP(id){let p=PRODUCTS.find(x=>x.id===id);let d=await api('/api/categories');CATS=d.categories;openM('Edit Product',prodForm(p));fillSub(p.category_id,p.subcategory_id);$('pcat').onchange=()=>fillSub($('pcat').value,'')}
async function saveP(id){let d={name:$('pn').value,price:+$('pp').value,old_price:+$('po').value,category_id:+$('pcat').value,subcategory_id:+$('psub').value,brand:$('pb').value,image:$('pi').value,affiliate_link:$('pa').value,affiliate_network:$('pnet').value,tags:$('pt').value,description:$('pd').value,active:$('act').checked,featured:$('feat').checked};await api(id?'/api/owner/products/'+id:'/api/owner/products',{method:id?'PUT':'POST',body:JSON.stringify(d)});closeM();oprod()}
async function delP(id){if(confirm('Delete product?')){await api('/api/owner/products/'+id,{method:'DELETE'});oprod()}}
function newCat(){openM('Add Category',`<input id="cn" placeholder="Category name"><textarea id="cs" placeholder="Subcategories, one per line" style="margin-top:8px"></textarea><button style="margin-top:8px" onclick="saveCat()">Save</button>`)}
function editCat(id){let c=CATS.find(x=>x.id===id);openM('Edit Category',`<input id="cn" value="${esc(c.name)}"><textarea id="cs" style="margin-top:8px">${esc(c.subs.map(x=>x.name).join('\\n'))}</textarea><button style="margin-top:8px" onclick="saveCat(${id})">Save</button>`)}
async function saveCat(id=0){let d={name:$('cn').value,subs:$('cs').value.split(/\\n|,/).map(x=>x.trim()).filter(Boolean)};await api(id?'/api/owner/categories/'+id:'/api/owner/categories',{method:id?'PUT':'POST',body:JSON.stringify(d)});closeM();ocat()}
async function delCat(id){if(confirm('Delete category?')){await api('/api/owner/categories/'+id,{method:'DELETE'});ocat()}}
async function cp(p){if(p==='home'){let d=await api('/api/products');PRODUCTS=d.products;$('cc').innerHTML=`<div class="hero"><h1>🛍️ Affiliate Market Pro</h1><p>ምርቶችን ይፈልጉ እና Affiliate link ይጠቀሙ።</p><button onclick="cp('products')">Shop Now</button></div><h3>⭐ Featured</h3><div class="products">${PRODUCTS.filter(x=>x.featured).map(cpc).join('')}</div>`}else if(p==='products'){let d=await api('/api/products');PRODUCTS=d.products;$('cc').innerHTML=`<div class="filters"><input id="cq" placeholder="Search..." oninput="filterC()"><select id="ccat" onchange="filterC()"><option value="">All categories</option>${CATS.map(c=>`<option>${esc(c.name)}</option>`).join('')}</select><select id="csub" onchange="filterC()"><option value="">All subcategories</option></select></div><div id="clist" class="products"></div>`;filterC()}else{let d=await api('/api/favorites');$('cc').innerHTML='<h2>❤️ Favorites</h2><div class="products">'+d.products.map(cpc).join('')+'</div>'}}
function cpc(p){return `<div class="card prod"><img src="${esc(p.image||'')}" onerror="this.style.display='none'"><span class="tag">${esc(p.category||'')}</span><h3>${esc(p.name)}</h3><p>${esc(p.description||'')}</p><div class="price">${money(p.price)}</div><button onclick="fav(${p.id})">❤️</button> <button onclick="buy(${p.id})">🔗 View / Buy</button></div>`}
function filterC(){let q=($('cq')?.value||'').toLowerCase(),c=$('ccat')?.value||'',s=$('csub')?.value||'';let x=PRODUCTS.filter(p=>p.name.toLowerCase().includes(q)&&(!c||p.category===c)&&(!s||p.subcategory===s));$('clist').innerHTML=x.map(cpc).join('')||'<p>No products found</p>'}
async function fav(id){await api('/api/favorites/'+id,{method:'POST'});alert('Favorites updated')}
async function buy(id){let d=await api('/api/click/'+id,{method:'POST'});if(d.url)window.open(d.url,'_blank')}
function openM(t,b){$('mt').textContent=t;$('mb').innerHTML=b;$('modal').classList.remove('hidden')}
function closeM(){$('modal').classList.add('hidden')}
(async()=>{try{let c=await api('/api/categories');CATS=c.categories}catch(e){};await start()})()
</script></body></html>
"""

init_db()
if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT","5000")),debug=False)

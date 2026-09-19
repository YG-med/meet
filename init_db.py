from pathlib import Path
import os
import hashlib
import secrets
from dotenv import load_dotenv
from db import get_db, connect_postgres, connection_summary
from storage import ensure_bucket, storage_configured

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env')
SCHEMA = (BASE / 'schema.sql').read_text(encoding='utf-8')

def generate_password_hash(password):
    salt=secrets.token_hex(16)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt.encode('ascii'),200000).hex()
    return f'pbkdf2_sha256$200000${salt}${digest}'

print('Database config:', connection_summary())

if os.getenv('RENDER') and not os.getenv('ADMIN_PASSWORD'):
    raise RuntimeError('ADMIN_PASSWORD is required on Render for the initial administrator account.')

if storage_configured():
    ensure_bucket()
    print('Supabase Storage bucket ready.')
else:
    print('WARNING: Supabase Storage is not configured. Image uploads on Render will be disabled.')

# 建立 schema
with connect_postgres() as pg:
    for stmt in SCHEMA.split(';'):
        stmt = stmt.strip()
        if stmt:
            pg.execute(stmt)
    pg.commit()

con = get_db()

# Admin
exists = con.execute('SELECT COUNT(*) FROM users').fetchone()[0]
if not exists:
    con.execute(
        'INSERT INTO users(username,display_name,password_hash,role) VALUES (?,?,?,?)',
        (os.getenv('ADMIN_USERNAME','admin'),os.getenv('ADMIN_DISPLAY_NAME','系統管理員'),generate_password_hash(os.getenv('ADMIN_PASSWORD','ChangeMe123!')),'admin')
    )

# Settings
defaults = {
    'site_name':'癒見｜慢性傷口照護網',
    'tagline':'看見傷口，找到對的照護。',
    'contact_email':'',
    'line_url':'',
    'facebook_url':'',
    'ga4_id':'',
    'site_url':('https://' + os.getenv('RENDER_EXTERNAL_HOSTNAME')) if os.getenv('RENDER_EXTERNAL_HOSTNAME') else 'http://127.0.0.1:5000'
}
for k,v in defaults.items():
    con.execute('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)',(k,v))

# Demo resources
if con.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 0:
    resources = [
        ('taipei-vgh-demo','台北榮民總醫院','醫院','台北市','北投區','台北市北投區','02-0000-0001','','','','示範院所資料，正式上線前需逐筆驗證。','糖尿病足,術後傷口,慢性傷口','依院所公告','',25.12,121.52,'',0,1,'示範資料',1),
        ('femh-demo','亞東紀念醫院','醫院','新北市','板橋區','新北市板橋區','02-0000-0002','','','','示範院所資料，正式上線前需逐筆驗證。','壓瘡,靜脈性潰瘍,術後傷口','依院所公告','',25.00,121.45,'',0,1,'示範資料',1),
        ('homecare-demo','安心居家護理所','居家護理所','新北市','三重區','新北市三重區','02-0000-0003','','','','示範居家護理資料。','居家換藥,壓瘡,臥床照護','預約制','新北市部分區域',None,None,'',0,1,'示範資料',1)
    ]
    con.executemany('''INSERT INTO resources
    (slug,name,type,city,district,address,phone,website,booking_url,email,description,services,service_hours,service_area,lat,lng,image_path,verified,featured,source_note,published)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', resources)

# Demo articles
if con.execute('SELECT COUNT(*) FROM articles').fetchone()[0] == 0:
    body1 = '''<h2>為什麼小傷口也不能輕忽？</h2>
<p>糖尿病患者可能同時存在周邊神經感覺下降、下肢循環問題或感染風險，因此傷口外觀看起來不大，不一定代表風險低。</p>
<h2>哪些情況建議提早就醫？</h2>
<ul><li>傷口持續沒有改善或逐漸擴大。</li><li>出現紅、腫、熱、痛、膿或異味。</li><li>合併發燒、畏寒或全身不舒服。</li></ul>
<p><strong>本頁目前為示範內容，正式上線前需由醫療團隊審閱。</strong></p>'''
    con.execute('''INSERT INTO articles
    (slug,title,category,summary,body,author,reviewer,references_text,conflict_disclosure,featured,published,meta_title,meta_description)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
    ('diabetic-foot-small-wound','糖尿病腳破皮很小，也需要看醫師嗎？','糖尿病足',
     '重點不是傷口看起來有多大，而是循環、感覺、感染與整體風險。',
     body1,'平台編輯團隊','待正式指派','正式版需補專業指引與文獻','無',1,1,
     '糖尿病腳破皮需要看醫師嗎？｜癒見','糖尿病足小傷口也可能需要評估，了解常見警訊與就醫時機。'))

# Experts
if con.execute('SELECT COUNT(*) FROM experts').fetchone()[0] == 0:
    con.executemany('''INSERT INTO experts(name,role_title,specialty,organization,bio,sort_order,published)
    VALUES (?,?,?,?,?,?,?)''',[
        ('待聘任','Medical Director','傷口醫療與內容治理','','正式人選確認後更新。',1,1),
        ('待聘任','Nursing Advisor','傷口照護與居家實務','','正式人選確認後更新。',2,1),
    ])

# Navigator
if con.execute('SELECT COUNT(*) FROM navigator_questions').fetchone()[0] == 0:
    qs=[
        ('傷口多久了？','了解傷口持續時間。',1,[('少於2週',0),('2–4週',1),('超過4週',1)]),
        ('是否有糖尿病？','糖尿病會提高部分傷口風險。',2,[('是',1),('否',0),('不確定',0)]),
        ('是否有紅腫熱痛、流膿或異味？','可能是需要優先評估的警訊。',3,[('是',2),('否',0),('不確定',1)]),
        ('是否發燒或明顯全身不適？','若有全身症狀，建議提高就醫優先級。',4,[('是',2),('否',0)])
    ]
    for q,help_text,order,opts in qs:
        cur=con.execute('INSERT INTO navigator_questions(question,help_text,sort_order) VALUES (?,?,?)',(q,help_text,order))
        qid=cur.lastrowid
        for i,(label,risk) in enumerate(opts,1):
            con.execute('INSERT INTO navigator_options(question_id,label,risk_level,sort_order) VALUES (?,?,?,?)',(qid,label,risk,i))

con.commit()
con.close()
print('Supabase 初始化完成')
print('管理員帳號：' + os.getenv('ADMIN_USERNAME','admin'))
print('管理員密碼由 ADMIN_PASSWORD 環境變數設定。')

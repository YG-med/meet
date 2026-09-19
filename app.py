import os, re, csv, io, secrets, json
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, Response, jsonify, g
import hashlib
from urllib.parse import urlparse
from dotenv import load_dotenv
from db import get_db
from storage import storage_configured, upload_filestorage

load_dotenv()

BASE = Path(__file__).resolve().parent
UPLOAD_DIR = BASE / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY","dev-yujian-change-this")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

ALLOWED_EXT = {"png","jpg","jpeg","webp"}

def generate_password_hash(password):
    salt=secrets.token_hex(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt.encode("ascii"),200000).hex()
    return f"pbkdf2_sha256$200000${salt}${digest}"

def check_password_hash(stored,password):
    try:
        scheme,iterations,salt,digest=stored.split("$",3)
        if scheme!="pbkdf2_sha256":
            return False
        calc=hashlib.pbkdf2_hmac("sha256",password.encode("utf-8"),salt.encode("ascii"),int(iterations)).hex()
        return secrets.compare_digest(calc,digest)
    except Exception:
        return False

def settings_dict():
    con=get_db()
    rows=con.execute("SELECT key,value FROM settings").fetchall()
    con.close()
    return {r["key"]:r["value"] for r in rows}

@app.context_processor
def inject_globals():
    return {"site_settings":settings_dict()}

def slugify(v):
    v=re.sub(r"[^a-zA-Z0-9\u4e00-\u9fff-]+","-", (v or "").strip())
    return re.sub(r"-+","-",v).strip("-").lower() or "item"

def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXT

def save_upload(file):
    if not file or not file.filename:
        return ""
    if not allowed_file(file.filename):
        raise ValueError("僅允許 png / jpg / jpeg / webp")
    if storage_configured():
        return upload_filestorage(file, ALLOWED_EXT)
    if os.getenv("RENDER"):
        raise RuntimeError("Render 上傳圖片需要設定 SUPABASE_URL 與 SUPABASE_SERVICE_ROLE_KEY。")
    ext=file.filename.rsplit(".",1)[1].lower()
    name=f"{secrets.token_hex(10)}.{ext}"
    file.save(UPLOAD_DIR/name)
    return f"uploads/{name}"

def media_url(path):
    if not path:
        return ""
    if str(path).startswith(("https://", "http://")):
        return path
    return url_for("static", filename=path)

@app.context_processor
def inject_media_url():
    return {"media_url": media_url}

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"]=secrets.token_urlsafe(24)
    return session["_csrf"]

@app.context_processor
def inject_csrf():
    return {"csrf_token":csrf_token}

def check_csrf():
    token=request.form.get("_csrf","")
    if not token or token != session.get("_csrf"):
        abort(400,"CSRF token invalid")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if not session.get("user_id"):
            return redirect(url_for("admin_login"))
        return fn(*args,**kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if not session.get("user_id"):
            return redirect(url_for("admin_login"))
        if session.get("role")!="admin":
            abort(403)
        return fn(*args,**kwargs)
    return wrapper

def audit(action,entity_type="",entity_id=None,detail=""):
    con=get_db()
    con.execute("INSERT INTO audit_logs(user_id,username,action,entity_type,entity_id,detail) VALUES (?,?,?,?,?,?)",
                (session.get("user_id"),session.get("username",""),action,entity_type,entity_id,detail))
    con.commit();con.close()

# ---------------- Anonymous traffic analytics ----------------
# Uses a random first-party visitor cookie. Raw IP addresses are intentionally not stored.
TRAFFIC_COOKIE = "yujian_vid"
TRAFFIC_COOKIE_MAX_AGE = 60 * 60 * 24 * 365
BOT_RE = re.compile(r"bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegrambot|uptimerobot|monitoring", re.I)

def _should_track_request():
    if request.method != "GET":
        return False
    path = request.path or "/"
    if path.startswith(("/admin", "/static/")):
        return False
    if path in {"/healthz", "/robots.txt", "/sitemap.xml", "/favicon.ico"}:
        return False
    ua = request.headers.get("User-Agent", "")
    if not ua or BOT_RE.search(ua):
        return False
    return True

@app.before_request
def prepare_traffic_tracking():
    if not _should_track_request():
        return
    visitor_id = request.cookies.get(TRAFFIC_COOKIE, "").strip()
    if not visitor_id or len(visitor_id) > 100:
        visitor_id = secrets.token_urlsafe(18)
        g._set_traffic_cookie = True
    g._traffic_visitor_id = visitor_id

@app.after_request
def record_traffic(response):
    visitor_id = getattr(g, "_traffic_visitor_id", None)
    if visitor_id and 200 <= response.status_code < 400:
        referrer_host = ""
        referrer = request.headers.get("Referer", "")
        if referrer:
            try:
                referrer_host = (urlparse(referrer).hostname or "")[:255]
            except Exception:
                referrer_host = ""
        con = None
        try:
            con = get_db()
            con.execute(
                "INSERT INTO traffic_events(visitor_id,path,referrer_host) VALUES (?,?,?)",
                (visitor_id, (request.path or "/")[:500], referrer_host),
            )
            con.commit()
        except Exception:
            # Analytics must never make the public website unavailable.
            app.logger.exception("Unable to record traffic event")
        finally:
            if con is not None:
                try:
                    con.close()
                except Exception:
                    pass

    if visitor_id and getattr(g, "_set_traffic_cookie", False):
        response.set_cookie(
            TRAFFIC_COOKIE,
            visitor_id,
            max_age=TRAFFIC_COOKIE_MAX_AGE,
            httponly=True,
            secure=bool(os.getenv("RENDER")) or request.is_secure,
            samesite="Lax",
        )
    return response

def traffic_summary(con):
    today = con.execute("""
        SELECT COUNT(DISTINCT visitor_id) AS visitors, COUNT(*) AS views
        FROM traffic_events
        WHERE timezone('Asia/Taipei', viewed_at)::date = timezone('Asia/Taipei', CURRENT_TIMESTAMP)::date
    """).fetchone()
    week = con.execute("""
        SELECT COUNT(DISTINCT visitor_id) AS visitors, COUNT(*) AS views
        FROM traffic_events
        WHERE timezone('Asia/Taipei', viewed_at)::date >= timezone('Asia/Taipei', CURRENT_TIMESTAMP)::date - 6
    """).fetchone()
    month = con.execute("""
        SELECT COUNT(DISTINCT visitor_id) AS visitors, COUNT(*) AS views
        FROM traffic_events
        WHERE timezone('Asia/Taipei', viewed_at)::date >= timezone('Asia/Taipei', CURRENT_TIMESTAMP)::date - 29
    """).fetchone()
    total = con.execute("SELECT COUNT(DISTINCT visitor_id) AS visitors, COUNT(*) AS views FROM traffic_events").fetchone()
    return {
        "today_visitors": today[0], "today_views": today[1],
        "week_visitors": week[0], "week_views": week[1],
        "month_visitors": month[0], "month_views": month[1],
        "total_visitors": total[0], "total_views": total[1],
    }

@app.get("/healthz")
def healthz():
    return jsonify({"status":"ok"}), 200

# ---------------- Public ----------------
@app.route("/")
def home():
    con=get_db()
    resources=con.execute("SELECT * FROM resources WHERE published=1 ORDER BY featured DESC, verified DESC, updated_at DESC LIMIT 6").fetchall()
    articles=con.execute("SELECT * FROM articles WHERE published=1 ORDER BY featured DESC, updated_at DESC LIMIT 8").fetchall()
    experts=con.execute("SELECT * FROM experts WHERE published=1 ORDER BY sort_order,id LIMIT 3").fetchall()
    con.close()
    return render_template("public/index.html",resources=resources,articles=articles,experts=experts)

@app.route("/resources")
def resources():
    q=request.args.get("q","").strip()
    city=request.args.get("city","").strip()
    type_=request.args.get("type","").strip()
    service=request.args.get("service","").strip()
    sql="SELECT * FROM resources WHERE published=1"
    params=[]
    if q:
        like=f"%{q}%";sql+=" AND (name LIKE ? OR city LIKE ? OR district LIKE ? OR services LIKE ? OR description LIKE ?)";params += [like]*5
    if city: sql+=" AND city=?";params.append(city)
    if type_: sql+=" AND type=?";params.append(type_)
    if service: sql+=" AND services LIKE ?";params.append(f"%{service}%")
    sql+=" ORDER BY featured DESC, verified DESC, updated_at DESC"
    con=get_db();rows=con.execute(sql,params).fetchall();con.close()
    return render_template("public/resources.html",rows=rows,q=q,city=city,type_=type_,service=service)

@app.route("/resources/<slug>")
def resource_detail(slug):
    con=get_db();r=con.execute("SELECT * FROM resources WHERE slug=? AND published=1",(slug,)).fetchone();con.close()
    if not r:abort(404)
    services=[x.strip() for x in (r["services"] or "").split(",") if x.strip()]
    return render_template("public/resource_detail.html",r=r,services=services)

@app.route("/knowledge")
def knowledge():
    category=request.args.get("category","")
    con=get_db()
    if category:
        rows=con.execute("SELECT * FROM articles WHERE published=1 AND category=? ORDER BY featured DESC,updated_at DESC",(category,)).fetchall()
    else:
        rows=con.execute("SELECT * FROM articles WHERE published=1 ORDER BY featured DESC,updated_at DESC").fetchall()
    cats=con.execute("SELECT DISTINCT category FROM articles WHERE published=1 AND category<>'' ORDER BY category").fetchall()
    con.close()
    return render_template("public/knowledge.html",rows=rows,cats=cats,category=category)

@app.route("/knowledge/<slug>")
def article_detail(slug):
    con=get_db();a=con.execute("SELECT * FROM articles WHERE slug=? AND published=1",(slug,)).fetchone();con.close()
    if not a:abort(404)
    return render_template("public/article_detail.html",a=a)

@app.route("/navigator",methods=["GET","POST"])
def navigator():
    con=get_db()
    questions=con.execute("SELECT * FROM navigator_questions WHERE published=1 ORDER BY sort_order,id").fetchall()
    opts={}
    for q in questions:
        opts[q["id"]]=con.execute("SELECT * FROM navigator_options WHERE question_id=? ORDER BY sort_order,id",(q["id"],)).fetchall()
    result=None
    if request.method=="POST":
        score=0
        for q in questions:
            val=request.form.get(f"q_{q['id']}")
            if val:
                op=con.execute("SELECT * FROM navigator_options WHERE id=? AND question_id=?",(val,q["id"])).fetchone()
                if op:score=max(score,op["risk_level"])
        if score>=2:
            result=("red","建議儘速尋求醫療評估","你的回答包含可能需要優先處理的警訊。若症狀明顯或快速惡化，請儘快就醫。")
        elif score==1:
            result=("yellow","建議近期安排專業傷口評估","你具有較需要注意的風險因素，建議近期尋求專業傷口評估。")
        else:
            result=("green","可先參考一般傷口衛教","若傷口持續不改善，或出現紅腫熱痛、膿、異味、發燒等變化，仍應就醫。")
    con.close()
    return render_template("public/navigator.html",questions=questions,opts=opts,result=result)

@app.route("/team")
def team():
    con=get_db();experts=con.execute("SELECT * FROM experts WHERE published=1 ORDER BY sort_order,id").fetchall();con.close()
    return render_template("public/team.html",experts=experts)

@app.route("/partner",methods=["GET","POST"])
def partner():
    if request.method=="POST":
        con=get_db()
        con.execute("""INSERT INTO partner_inquiries(name,organization,email,phone,inquiry_type,message)
        VALUES (?,?,?,?,?,?)""",(request.form.get("name"),request.form.get("organization"),request.form.get("email"),
        request.form.get("phone"),request.form.get("inquiry_type"),request.form.get("message")))
        con.commit();con.close()
        flash("已收到您的合作需求，我們會由平台團隊後續聯繫。","success")
        return redirect(url_for("partner"))
    return render_template("public/partner.html")

@app.post("/subscribe")
def subscribe():
    email=request.form.get("email","").strip().lower()
    if email:
        con=get_db()
        try:
            con.execute("INSERT OR IGNORE INTO subscribers(email,source) VALUES (?,?)",(email,request.form.get("source","website")))
            con.commit()
        finally:
            con.close()
    flash("訂閱完成。","success")
    return redirect(request.referrer or url_for("home"))

@app.route("/about")
def about():
    return render_template("public/about.html")

@app.route("/robots.txt")
def robots():
    s=settings_dict();site=s.get("site_url","http://127.0.0.1:5000").rstrip("/")
    return Response(f"User-agent: *\\nAllow: /\\nSitemap: {site}/sitemap.xml\\n",mimetype="text/plain")

@app.route("/sitemap.xml")
def sitemap():
    s=settings_dict();site=s.get("site_url","http://127.0.0.1:5000").rstrip("/")
    con=get_db()
    rs=con.execute("SELECT slug FROM resources WHERE published=1").fetchall()
    arts=con.execute("SELECT slug FROM articles WHERE published=1").fetchall()
    con.close()
    paths=["/","/resources","/knowledge","/navigator","/team","/partner","/about"]
    paths += [f"/resources/{r['slug']}" for r in rs]
    paths += [f"/knowledge/{a['slug']}" for a in arts]
    xml=['<?xml version="1.0" encoding="UTF-8"?>','<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    xml += [f"<url><loc>{site}{p}</loc></url>" for p in paths]
    xml.append("</urlset>")
    return Response("\\n".join(xml),mimetype="application/xml")

# ---------------- Auth ----------------
@app.route("/admin/login",methods=["GET","POST"])
def admin_login():
    if request.method=="POST":
        check_csrf()
        con=get_db();u=con.execute("SELECT * FROM users WHERE username=? AND active=1",(request.form.get("username"),)).fetchone()
        if u and check_password_hash(u["password_hash"],request.form.get("password","")):
            session.clear()
            session["user_id"]=u["id"];session["username"]=u["username"];session["display_name"]=u["display_name"];session["role"]=u["role"]
            con.execute("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?",(u["id"],));con.commit();con.close()
            return redirect(url_for("admin_dashboard"))
        con.close();flash("帳號或密碼錯誤。","error")
    return render_template("admin/login.html")

@app.route("/admin/logout")
def admin_logout():
    session.clear();return redirect(url_for("admin_login"))

# ---------------- Dashboard ----------------
@app.route("/admin")
@login_required
def admin_dashboard():
    con=get_db()
    counts={
      "resources":con.execute("SELECT COUNT(*) FROM resources").fetchone()[0],
      "verified":con.execute("SELECT COUNT(*) FROM resources WHERE verified=1").fetchone()[0],
      "articles":con.execute("SELECT COUNT(*) FROM articles").fetchone()[0],
      "experts":con.execute("SELECT COUNT(*) FROM experts").fetchone()[0],
      "inquiries":con.execute("SELECT COUNT(*) FROM partner_inquiries WHERE status='new'").fetchone()[0],
      "subscribers":con.execute("SELECT COUNT(*) FROM subscribers WHERE active=1").fetchone()[0],
    }
    traffic=traffic_summary(con)
    recent=con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10").fetchall()
    con.close()
    return render_template("admin/dashboard.html",counts=counts,traffic=traffic,recent=recent)


@app.route("/admin/analytics")
@login_required
def admin_analytics():
    con=get_db()
    summary=traffic_summary(con)
    daily=con.execute("""
        WITH days AS (
          SELECT generate_series(
            timezone('Asia/Taipei', CURRENT_TIMESTAMP)::date - 13,
            timezone('Asia/Taipei', CURRENT_TIMESTAMP)::date,
            interval '1 day'
          )::date AS day
        )
        SELECT to_char(days.day,'MM/DD') AS day_label,
               COUNT(DISTINCT t.visitor_id) AS visitors,
               COUNT(t.id) AS views
        FROM days
        LEFT JOIN traffic_events t
          ON timezone('Asia/Taipei', t.viewed_at)::date = days.day
        GROUP BY days.day
        ORDER BY days.day
    """).fetchall()
    top_pages=con.execute("""
        SELECT path, COUNT(DISTINCT visitor_id) AS visitors, COUNT(*) AS views
        FROM traffic_events
        WHERE timezone('Asia/Taipei', viewed_at)::date >= timezone('Asia/Taipei', CURRENT_TIMESTAMP)::date - 29
        GROUP BY path
        ORDER BY views DESC, visitors DESC
        LIMIT 12
    """).fetchall()
    sources=con.execute("""
        SELECT CASE WHEN referrer_host='' THEN '直接進入／未知' ELSE referrer_host END AS source,
               COUNT(DISTINCT visitor_id) AS visitors, COUNT(*) AS views
        FROM traffic_events
        WHERE timezone('Asia/Taipei', viewed_at)::date >= timezone('Asia/Taipei', CURRENT_TIMESTAMP)::date - 29
        GROUP BY 1
        ORDER BY visitors DESC, views DESC
        LIMIT 10
    """).fetchall()
    con.close()
    max_daily_views=max([r["views"] for r in daily] or [1]) or 1
    return render_template(
        "admin/analytics.html",
        summary=summary, daily=daily, top_pages=top_pages, sources=sources, max_daily_views=max_daily_views
    )

# ---------------- Resources CRUD ----------------
@app.route("/admin/resources")
@login_required
def admin_resources():
    con=get_db();rows=con.execute("SELECT * FROM resources ORDER BY updated_at DESC").fetchall();con.close()
    return render_template("admin/resources.html",rows=rows)

@app.route("/admin/resources/new",methods=["GET","POST"])
@login_required
def admin_resource_new():
    if request.method=="POST":
        check_csrf()
        f=request.form
        img=save_upload(request.files.get("image")) if request.files.get("image") else ""
        con=get_db()
        cur=con.execute("""INSERT INTO resources
        (slug,name,type,city,district,address,phone,website,booking_url,email,description,services,service_hours,service_area,lat,lng,image_path,verified,featured,source_note,published,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
        (f.get("slug") or slugify(f.get("name")),f.get("name"),f.get("type"),f.get("city"),f.get("district"),f.get("address"),
         f.get("phone"),f.get("website"),f.get("booking_url"),f.get("email"),f.get("description"),f.get("services"),f.get("service_hours"),
         f.get("service_area"),f.get("lat") or None,f.get("lng") or None,img,1 if f.get("verified") else 0,1 if f.get("featured") else 0,
         f.get("source_note"),1 if f.get("published") else 0))
        con.commit();rid=cur.lastrowid;con.close()
        audit("create","resource",rid,f.get("name",""));flash("照護資源已新增。","success")
        return redirect(url_for("admin_resources"))
    return render_template("admin/resource_form.html",r=None)

@app.route("/admin/resources/<int:id>/edit",methods=["GET","POST"])
@login_required
def admin_resource_edit(id):
    con=get_db();r=con.execute("SELECT * FROM resources WHERE id=?",(id,)).fetchone()
    if not r:con.close();abort(404)
    if request.method=="POST":
        check_csrf();f=request.form
        img=r["image_path"]
        if request.files.get("image") and request.files["image"].filename:
            img=save_upload(request.files["image"])
        con.execute("""UPDATE resources SET slug=?,name=?,type=?,city=?,district=?,address=?,phone=?,website=?,booking_url=?,email=?,
        description=?,services=?,service_hours=?,service_area=?,lat=?,lng=?,image_path=?,verified=?,featured=?,source_note=?,published=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
        (f.get("slug") or slugify(f.get("name")),f.get("name"),f.get("type"),f.get("city"),f.get("district"),f.get("address"),
         f.get("phone"),f.get("website"),f.get("booking_url"),f.get("email"),f.get("description"),f.get("services"),f.get("service_hours"),
         f.get("service_area"),f.get("lat") or None,f.get("lng") or None,img,1 if f.get("verified") else 0,1 if f.get("featured") else 0,
         f.get("source_note"),1 if f.get("published") else 0,id))
        con.commit();con.close();audit("update","resource",id,f.get("name",""));flash("照護資源已更新。","success")
        return redirect(url_for("admin_resources"))
    con.close();return render_template("admin/resource_form.html",r=r)

@app.post("/admin/resources/<int:id>/delete")
@login_required
def admin_resource_delete(id):
    check_csrf();con=get_db();r=con.execute("SELECT name FROM resources WHERE id=?",(id,)).fetchone()
    con.execute("DELETE FROM resources WHERE id=?",(id,));con.commit();con.close()
    audit("delete","resource",id,r["name"] if r else "");flash("已刪除。","success");return redirect(url_for("admin_resources"))

# ---------------- Articles ----------------
@app.route("/admin/articles")
@login_required
def admin_articles():
    con=get_db();rows=con.execute("SELECT * FROM articles ORDER BY updated_at DESC").fetchall();con.close()
    return render_template("admin/articles.html",rows=rows)

@app.route("/admin/articles/new",methods=["GET","POST"])
@login_required
def admin_article_new():
    if request.method=="POST":
        check_csrf();f=request.form;img=save_upload(request.files.get("cover")) if request.files.get("cover") else ""
        con=get_db();cur=con.execute("""INSERT INTO articles
        (slug,title,category,summary,body,author,reviewer,references_text,conflict_disclosure,cover_image,sponsored,featured,meta_title,meta_description,published,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",
        (f.get("slug") or slugify(f.get("title")),f.get("title"),f.get("category"),f.get("summary"),f.get("body"),f.get("author"),
         f.get("reviewer"),f.get("references_text"),f.get("conflict_disclosure"),img,1 if f.get("sponsored") else 0,1 if f.get("featured") else 0,
         f.get("meta_title"),f.get("meta_description"),1 if f.get("published") else 0))
        con.commit();aid=cur.lastrowid;con.close();audit("create","article",aid,f.get("title",""));flash("文章已新增。","success")
        return redirect(url_for("admin_articles"))
    return render_template("admin/article_form.html",a=None)

@app.route("/admin/articles/<int:id>/edit",methods=["GET","POST"])
@login_required
def admin_article_edit(id):
    con=get_db();a=con.execute("SELECT * FROM articles WHERE id=?",(id,)).fetchone()
    if not a:con.close();abort(404)
    if request.method=="POST":
        check_csrf();f=request.form;img=a["cover_image"]
        if request.files.get("cover") and request.files["cover"].filename:
            img=save_upload(request.files["cover"])
        con.execute("""UPDATE articles SET slug=?,title=?,category=?,summary=?,body=?,author=?,reviewer=?,references_text=?,conflict_disclosure=?,
        cover_image=?,sponsored=?,featured=?,meta_title=?,meta_description=?,published=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
        (f.get("slug") or slugify(f.get("title")),f.get("title"),f.get("category"),f.get("summary"),f.get("body"),f.get("author"),
         f.get("reviewer"),f.get("references_text"),f.get("conflict_disclosure"),img,1 if f.get("sponsored") else 0,1 if f.get("featured") else 0,
         f.get("meta_title"),f.get("meta_description"),1 if f.get("published") else 0,id))
        con.commit();con.close();audit("update","article",id,f.get("title",""));flash("文章已更新。","success")
        return redirect(url_for("admin_articles"))
    con.close();return render_template("admin/article_form.html",a=a)

@app.post("/admin/articles/<int:id>/delete")
@login_required
def admin_article_delete(id):
    check_csrf();con=get_db();a=con.execute("SELECT title FROM articles WHERE id=?",(id,)).fetchone();con.execute("DELETE FROM articles WHERE id=?",(id,));con.commit();con.close()
    audit("delete","article",id,a["title"] if a else "");flash("文章已刪除。","success");return redirect(url_for("admin_articles"))

# ---------------- Experts ----------------
@app.route("/admin/experts")
@login_required
def admin_experts():
    con=get_db();rows=con.execute("SELECT * FROM experts ORDER BY sort_order,id").fetchall();con.close()
    return render_template("admin/experts.html",rows=rows)

@app.route("/admin/experts/new",methods=["GET","POST"])
@login_required
def admin_expert_new():
    if request.method=="POST":
        check_csrf();f=request.form;img=save_upload(request.files.get("image")) if request.files.get("image") else ""
        con=get_db();cur=con.execute("""INSERT INTO experts(name,role_title,specialty,organization,bio,image_path,sort_order,published,updated_at)
        VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)""",(f.get("name"),f.get("role_title"),f.get("specialty"),f.get("organization"),f.get("bio"),img,
        int(f.get("sort_order") or 0),1 if f.get("published") else 0));con.commit();eid=cur.lastrowid;con.close()
        audit("create","expert",eid,f.get("name",""));flash("專業人員已新增。","success");return redirect(url_for("admin_experts"))
    return render_template("admin/expert_form.html",e=None)

@app.route("/admin/experts/<int:id>/edit",methods=["GET","POST"])
@login_required
def admin_expert_edit(id):
    con=get_db();e=con.execute("SELECT * FROM experts WHERE id=?",(id,)).fetchone()
    if not e:con.close();abort(404)
    if request.method=="POST":
        check_csrf();f=request.form;img=e["image_path"]
        if request.files.get("image") and request.files["image"].filename:img=save_upload(request.files["image"])
        con.execute("""UPDATE experts SET name=?,role_title=?,specialty=?,organization=?,bio=?,image_path=?,sort_order=?,published=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
        (f.get("name"),f.get("role_title"),f.get("specialty"),f.get("organization"),f.get("bio"),img,int(f.get("sort_order") or 0),1 if f.get("published") else 0,id))
        con.commit();con.close();audit("update","expert",id,f.get("name",""));flash("專業人員已更新。","success");return redirect(url_for("admin_experts"))
    con.close();return render_template("admin/expert_form.html",e=e)

@app.post("/admin/experts/<int:id>/delete")
@login_required
def admin_expert_delete(id):
    check_csrf();con=get_db();con.execute("DELETE FROM experts WHERE id=?",(id,));con.commit();con.close();audit("delete","expert",id,"");flash("已刪除。","success");return redirect(url_for("admin_experts"))

# ---------------- Navigator ----------------
@app.route("/admin/navigator")
@login_required
def admin_navigator():
    con=get_db();qs=con.execute("SELECT * FROM navigator_questions ORDER BY sort_order,id").fetchall()
    options={}
    for q in qs:options[q["id"]]=con.execute("SELECT * FROM navigator_options WHERE question_id=? ORDER BY sort_order,id",(q["id"],)).fetchall()
    con.close();return render_template("admin/navigator.html",qs=qs,options=options)

@app.route("/admin/navigator/new",methods=["GET","POST"])
@login_required
def admin_navigator_new():
    if request.method=="POST":
        check_csrf();f=request.form;con=get_db()
        cur=con.execute("INSERT INTO navigator_questions(question,help_text,sort_order,published) VALUES (?,?,?,?)",
        (f.get("question"),f.get("help_text"),int(f.get("sort_order") or 0),1 if f.get("published") else 0))
        qid=cur.lastrowid
        labels=request.form.getlist("option_label");risks=request.form.getlist("option_risk")
        for i,label in enumerate(labels):
            if label.strip():
                con.execute("INSERT INTO navigator_options(question_id,label,risk_level,sort_order) VALUES (?,?,?,?)",(qid,label.strip(),int(risks[i] or 0),i+1))
        con.commit();con.close();audit("create","navigator_question",qid,f.get("question",""));flash("導航題目已新增。","success");return redirect(url_for("admin_navigator"))
    return render_template("admin/navigator_form.html",q=None,opts=[])

@app.route("/admin/navigator/<int:id>/edit",methods=["GET","POST"])
@login_required
def admin_navigator_edit(id):
    con=get_db();q=con.execute("SELECT * FROM navigator_questions WHERE id=?",(id,)).fetchone();opts=con.execute("SELECT * FROM navigator_options WHERE question_id=? ORDER BY sort_order,id",(id,)).fetchall()
    if not q:con.close();abort(404)
    if request.method=="POST":
        check_csrf();f=request.form
        con.execute("UPDATE navigator_questions SET question=?,help_text=?,sort_order=?,published=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (f.get("question"),f.get("help_text"),int(f.get("sort_order") or 0),1 if f.get("published") else 0,id))
        con.execute("DELETE FROM navigator_options WHERE question_id=?",(id,))
        labels=request.form.getlist("option_label");risks=request.form.getlist("option_risk")
        for i,label in enumerate(labels):
            if label.strip():
                con.execute("INSERT INTO navigator_options(question_id,label,risk_level,sort_order) VALUES (?,?,?,?)",(id,label.strip(),int(risks[i] or 0),i+1))
        con.commit();con.close();audit("update","navigator_question",id,f.get("question",""));flash("導航題目已更新。","success");return redirect(url_for("admin_navigator"))
    con.close();return render_template("admin/navigator_form.html",q=q,opts=opts)

@app.post("/admin/navigator/<int:id>/delete")
@login_required
def admin_navigator_delete(id):
    check_csrf();con=get_db();con.execute("DELETE FROM navigator_questions WHERE id=?",(id,));con.commit();con.close();audit("delete","navigator_question",id,"");flash("已刪除。","success");return redirect(url_for("admin_navigator"))

# ---------------- Inquiries / Subscribers ----------------
@app.route("/admin/inquiries")
@login_required
def admin_inquiries():
    con=get_db();rows=con.execute("SELECT * FROM partner_inquiries ORDER BY created_at DESC").fetchall();con.close()
    return render_template("admin/inquiries.html",rows=rows)

@app.post("/admin/inquiries/<int:id>/status")
@login_required
def admin_inquiry_status(id):
    check_csrf();status=request.form.get("status","new");con=get_db();con.execute("UPDATE partner_inquiries SET status=? WHERE id=?",(status,id));con.commit();con.close();audit("update","inquiry",id,status);return redirect(url_for("admin_inquiries"))

@app.route("/admin/subscribers")
@login_required
def admin_subscribers():
    con=get_db();rows=con.execute("SELECT * FROM subscribers ORDER BY created_at DESC").fetchall();con.close()
    return render_template("admin/subscribers.html",rows=rows)

@app.post("/admin/subscribers/<int:id>/toggle")
@login_required
def admin_subscriber_toggle(id):
    check_csrf();con=get_db();con.execute("UPDATE subscribers SET active=CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?",(id,));con.commit();con.close();audit("toggle","subscriber",id,"");return redirect(url_for("admin_subscribers"))

@app.route("/admin/subscribers/export.csv")
@login_required
def export_subscribers():
    con=get_db();rows=con.execute("SELECT email,source,active,created_at FROM subscribers ORDER BY created_at DESC").fetchall();con.close()
    output=io.StringIO();w=csv.writer(output);w.writerow(["email","source","active","created_at"])
    for r in rows:w.writerow([r["email"],r["source"],r["active"],r["created_at"]])
    return Response("\\ufeff"+output.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=subscribers.csv"})

# ---------------- Settings / Users / Logs ----------------
@app.route("/admin/settings",methods=["GET","POST"])
@admin_required
def admin_settings():
    con=get_db()
    if request.method=="POST":
        check_csrf()
        for key in ["site_name","tagline","contact_email","line_url","facebook_url","ga4_id","site_url"]:
            con.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(key,request.form.get(key,"")))
        con.commit();audit("update","settings",None,"網站設定");flash("設定已儲存。","success")
    rows=con.execute("SELECT key,value FROM settings").fetchall();con.close()
    return render_template("admin/settings.html",settings={r["key"]:r["value"] for r in rows})

@app.route("/admin/users")
@admin_required
def admin_users():
    con=get_db();rows=con.execute("SELECT id,username,display_name,role,active,created_at,last_login_at FROM users ORDER BY id").fetchall();con.close()
    return render_template("admin/users.html",rows=rows)

@app.route("/admin/users/new",methods=["GET","POST"])
@admin_required
def admin_user_new():
    if request.method=="POST":
        check_csrf();f=request.form;con=get_db()
        con.execute("INSERT INTO users(username,display_name,password_hash,role,active) VALUES (?,?,?,?,?)",
        (f.get("username"),f.get("display_name"),generate_password_hash(f.get("password")),f.get("role","editor"),1))
        con.commit();con.close();audit("create","user",None,f.get("username",""));flash("管理員已新增。","success");return redirect(url_for("admin_users"))
    return render_template("admin/user_form.html",u=None)

@app.route("/admin/users/<int:id>/edit",methods=["GET","POST"])
@admin_required
def admin_user_edit(id):
    con=get_db();u=con.execute("SELECT * FROM users WHERE id=?",(id,)).fetchone()
    if not u:con.close();abort(404)
    if request.method=="POST":
        check_csrf();f=request.form
        if f.get("password"):
            con.execute("UPDATE users SET display_name=?,role=?,active=?,password_hash=? WHERE id=?",
            (f.get("display_name"),f.get("role"),1 if f.get("active") else 0,generate_password_hash(f.get("password")),id))
        else:
            con.execute("UPDATE users SET display_name=?,role=?,active=? WHERE id=?",
            (f.get("display_name"),f.get("role"),1 if f.get("active") else 0,id))
        con.commit();con.close();audit("update","user",id,u["username"]);flash("管理員已更新。","success");return redirect(url_for("admin_users"))
    con.close();return render_template("admin/user_form.html",u=u)

@app.route("/admin/logs")
@admin_required
def admin_logs():
    con=get_db();rows=con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 300").fetchall();con.close()
    return render_template("admin/logs.html",rows=rows)

@app.route("/admin/backup")
@admin_required
def admin_backup():
    tables=["users","resources","articles","experts","navigator_questions","navigator_options",
            "partner_inquiries","subscribers","settings","audit_logs"]
    con=get_db();backup={}
    try:
        for table in tables:
            rows=con.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            backup[table]=[dict(r.items()) for r in rows]
    finally:
        con.close()
    data=json.dumps(backup,ensure_ascii=False,indent=2,default=str)
    return Response("\ufeff"+data,mimetype="application/json",headers={"Content-Disposition":"attachment; filename=yujian-supabase-backup.json"})

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")

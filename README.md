# 癒見｜Render + GitHub + Supabase 部署版

本版本已針對 Render Web Service 調整，可由 GitHub 自動部署。

## 架構

- GitHub：保存程式碼
- Render：執行 Flask / Gunicorn
- Supabase PostgreSQL：永久資料庫
- Supabase Storage：永久圖片儲存

> Render 免費 Web Service 的本機檔案系統不是永久儲存，因此正式上線時圖片請使用 Supabase Storage。

## 1. 上傳到 GitHub

建立一個新的 GitHub repository，將本資料夾「裡面的所有檔案」放到 repository 根目錄。

不要上傳 `.env`。本專案的 `.gitignore` 已排除 `.env`。

## 2. Supabase 要準備的資料

### PostgreSQL
在 Supabase Dashboard > Connect > Session pooler 複製：

- Host -> `SUPABASE_DB_HOST`
- Port -> 5432
- Database -> postgres
- User -> `SUPABASE_DB_USER`
- Database password -> `SUPABASE_DB_PASSWORD`

### Storage
在 Supabase Project Settings / API 取得：

- Project URL -> `SUPABASE_URL`
- service_role key -> `SUPABASE_SERVICE_ROLE_KEY`

`service_role` 是高權限密鑰，只能放在 Render 的 Secret Environment Variable，絕對不要提交到 GitHub。

## 3. 用 Render Blueprint 部署

1. 登入 Render，連接 GitHub。
2. 選 New > Blueprint。
3. 選擇這個 GitHub repository。
4. Render 會自動讀取根目錄的 `render.yaml`。
5. 第一次建立時，Render 會要求填入 `sync: false` 的秘密環境變數。
6. 填完後建立服務。

需要填：

- `ADMIN_PASSWORD`：後台 admin 初始密碼
- `SUPABASE_DB_HOST`
- `SUPABASE_DB_USER`
- `SUPABASE_DB_PASSWORD`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

其他值已由 `render.yaml` 帶入。

## 4. 啟動流程

Render 每次啟動會執行：

```bash
python init_db.py
gunicorn app:app --bind 0.0.0.0:$PORT
```

`init_db.py` 是可重複執行的：資料表已存在時不會重建資料；只有空資料庫才會建立初始管理員與示範資料。

## 5. 後台

網址：

```text
https://你的-render-網址.onrender.com/admin/login
```

帳號預設是 `admin`，密碼是你在 Render 設定的 `ADMIN_PASSWORD`。

## 6. 健康檢查

```text
/healthz
```

正常會回傳：

```json
{"status":"ok"}
```

## 7. 圖片

若 `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` 已設定，後台新增院所、文章封面與專家照片會直接上傳到 Supabase Storage 的 `yujian-media` public bucket。

Render 環境若沒有設定 Storage 憑證，後台圖片上傳會阻止寫入，避免你誤以為圖片已永久保存。

## 8. 本機測試

複製 `.env.example` 為 `.env`，填入自己的 Supabase 設定後：

```bash
pip install -r requirements.txt
python init_db.py
python app.py
```

瀏覽：http://127.0.0.1:5000


## v5：後台網站流量統計
- 自動記錄公開頁面的瀏覽事件。
- 後台 `/admin` 顯示今日、近 7 日、近 30 日與累計匿名訪客。
- `/admin/analytics` 提供 14 天趨勢、熱門頁面與來源。
- 不儲存原始 IP；以第一方隨機 Cookie `yujian_vid` 做匿名訪客去重。
- 每次 Render 部署會執行 `init_db.py`，既有 Supabase 會自動新增 `traffic_events` 表與索引，不會刪除原資料。

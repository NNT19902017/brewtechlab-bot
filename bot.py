import os
import re
import sqlite3
from datetime import datetime, UTC, timedelta
from urllib.parse import urlparse

import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
    CallbackQueryHandler,
)

# === CONFIG ===
TOKEN = os.getenv("TOKEN", "")

# Put your Telegram numeric user_id here (get it via /myid)
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))

DONATE_URL = "https://buymeacoffee.com/brewtechlab"

FREE_MAX_MB = 20
PREMIUM_MAX_MB = 50  # change to 100 if you want
FREE_MAX_BYTES = FREE_MAX_MB * 1024 * 1024
PREMIUM_MAX_BYTES = PREMIUM_MAX_MB * 1024 * 1024

DB_PATH = "brewtechlab_bot.db"
URL_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)

# Callback data
CB_HELP = "cb_help"
CB_DONATE = "cb_donate"
CB_STATS = "cb_stats"
CB_PREMIUM = "cb_premium"


# === DATABASE ===
def db_connect():
    return sqlite3.connect(DB_PATH)


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def db_init():
    con = db_connect()
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            first_seen TEXT,
            last_seen TEXT,
            messages_count INTEGER DEFAULT 0,
            files_sent INTEGER DEFAULT 0,
            donate_opened INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            user_id INTEGER,
            event TEXT,
            detail TEXT
        )
    """)

    # Premium table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS premium (
            user_id INTEGER PRIMARY KEY,
            expires_at TEXT,
            granted_by INTEGER,
            granted_at TEXT
        )
    """)

    # Premium requests (manual review)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS premium_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ts TEXT,
            note TEXT,
            status TEXT DEFAULT 'pending' -- pending/approved/rejected
        )
    """)

    con.commit()
    con.close()


def upsert_user(update: Update):
    u = update.effective_user
    if not u:
        return
    now = now_utc()
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO users (user_id, username, first_name, last_name, first_seen, last_seen, messages_count, files_sent, donate_opened)
        VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0)
        ON CONFLICT(user_id) DO UPDATE SET
            username=excluded.username,
            first_name=excluded.first_name,
            last_name=excluded.last_name,
            last_seen=excluded.last_seen
    """, (u.id, u.username, u.first_name, u.last_name, now, now))
    con.commit()
    con.close()


def add_log(user_id: int | None, event: str, detail: str = ""):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO logs (ts, user_id, event, detail) VALUES (?, ?, ?, ?)",
        (now_utc(), user_id, event, detail),
    )
    con.commit()
    con.close()


def inc_messages(user_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET messages_count = messages_count + 1, last_seen = ? WHERE user_id = ?",
        (now_utc(), user_id),
    )
    con.commit()
    con.close()


def inc_files_sent(user_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET files_sent = files_sent + 1, last_seen = ? WHERE user_id = ?",
        (now_utc(), user_id),
    )
    con.commit()
    con.close()


def inc_donate_opened(user_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET donate_opened = donate_opened + 1, last_seen = ? WHERE user_id = ?",
        (now_utc(), user_id),
    )
    con.commit()
    con.close()


def get_user_stats(user_id: int) -> tuple[int, int, int] | None:
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "SELECT messages_count, files_sent, donate_opened FROM users WHERE user_id = ?",
        (user_id,),
    )
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    return int(row[0]), int(row[1]), int(row[2])


# === PREMIUM ===
def get_premium_expiry(user_id: int) -> datetime | None:
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT expires_at FROM premium WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    con.close()
    if not row or not row[0]:
        return None
    try:
        return datetime.fromisoformat(row[0])
    except Exception:
        return None


def is_premium(user_id: int) -> bool:
    exp = get_premium_expiry(user_id)
    if not exp:
        return False
    return exp > datetime.now(UTC)


def set_premium(user_id: int, days: int, granted_by: int):
    exp = datetime.now(UTC) + timedelta(days=days)
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO premium (user_id, expires_at, granted_by, granted_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            expires_at=excluded.expires_at,
            granted_by=excluded.granted_by,
            granted_at=excluded.granted_at
    """, (user_id, exp.isoformat(), granted_by, now_utc()))
    con.commit()
    con.close()


def revoke_premium(user_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute("DELETE FROM premium WHERE user_id = ?", (user_id,))
    con.commit()
    con.close()


def add_premium_request(user_id: int, note: str):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO premium_requests (user_id, ts, note, status) VALUES (?, ?, ?, 'pending')",
        (user_id, now_utc(), note[:500]),
    )
    con.commit()
    con.close()


def list_pending_requests(limit: int = 10):
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        SELECT id, user_id, ts, note
        FROM premium_requests
        WHERE status='pending'
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    con.close()
    return rows


def mark_request(id_: int, status: str):
    con = db_connect()
    cur = con.cursor()
    cur.execute("UPDATE premium_requests SET status=? WHERE id=?", (status, id_))
    con.commit()
    con.close()


# === HELPERS ===
def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0"}
        return (parsed.hostname or "").lower() not in blocked_hosts
    except Exception:
        return False


def extract_filename(url: str, content_disposition: str | None) -> str:
    if content_disposition:
        match = re.search(
            r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?',
            content_disposition,
            re.IGNORECASE,
        )
        if match:
            return os.path.basename(match.group(1)).strip() or "download"

    path = urlparse(url).path
    return os.path.basename(path) or "download"


def donate_url_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("☕ Buy Me a Coffee", url=DONATE_URL)]]
    )


def home_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("⬇️ How to use", callback_data=CB_HELP)],
            [InlineKeyboardButton("☕ Donate", callback_data=CB_DONATE)],
            [InlineKeyboardButton("⭐ Premium", callback_data=CB_PREMIUM)],
            [InlineKeyboardButton("📊 Stats", callback_data=CB_STATS)],
        ]
    )


def help_text() -> str:
    return (
        "⬇️ How to use\n\n"
        "1) Send a DIRECT file link (mp4/mp3/pdf/jpg/zip...)\n"
        f"2) Free max size: {FREE_MAX_MB} MB\n"
        f"3) Premium max size: {PREMIUM_MAX_MB} MB\n\n"
        "Notes:\n"
        "- Some websites block automated downloads (HTTP 403).\n"
        "- Links that require login/cookies may fail (HTTP 401).\n\n"
        "Commands:\n"
        "/start  /help  /donate  /premium  /stats\n"
        "/requestpremium <your note>\n"
        "/myid"
    )


def premium_text(user_id: int) -> str:
    if is_premium(user_id):
        exp = get_premium_expiry(user_id)
        return f"⭐ Premium: ACTIVE\nExpires: {exp.isoformat() if exp else 'unknown'}\nMax size: {PREMIUM_MAX_MB} MB"
    return f"⭐ Premium: NOT ACTIVE\nFree max size: {FREE_MAX_MB} MB\nPremium max size: {PREMIUM_MAX_MB} MB"


def allowed_max_bytes(user_id: int) -> int:
    return PREMIUM_MAX_BYTES if is_premium(user_id) else FREE_MAX_BYTES


# === COMMANDS ===
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    add_log(u.id if u else None, "start")

    await update.message.reply_text(
        "👋 Welcome to BrewTechLab Downloader!\n\n"
        "Send me a DIRECT file link and I'll download + upload it back to you.\n"
        f"Free max: {FREE_MAX_MB} MB | Premium max: {PREMIUM_MAX_MB} MB",
        reply_markup=home_keyboard(),
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    add_log(u.id if u else None, "help_command")
    await update.message.reply_text(help_text(), reply_markup=home_keyboard())


async def donate_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if u:
        inc_donate_opened(u.id)
        add_log(u.id, "donate_command", DONATE_URL)

    await update.message.reply_text(
        "☕ Support BrewTechLab\n\n"
        "Donate here and then send /requestpremium with your donation ID or a short note.\n"
        "Example:\n"
        "/requestpremium BMC receipt #XXXX\n",
        reply_markup=donate_url_keyboard(),
        disable_web_page_preview=True,
    )


async def stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if not u:
        return

    stats = get_user_stats(u.id)
    add_log(u.id, "stats_command")

    if not stats:
        await update.message.reply_text("No stats yet.", reply_markup=home_keyboard())
        return

    msgs, files, donate = stats
    prem = "ACTIVE" if is_premium(u.id) else "NO"
    await update.message.reply_text(
        f"📊 Your stats\n\nMessages: {msgs}\nFiles sent: {files}\nDonate opens: {donate}\nPremium: {prem}",
        reply_markup=home_keyboard(),
    )


async def premium_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if not u:
        return
    add_log(u.id, "premium_command")
    await update.message.reply_text(premium_text(u.id), reply_markup=home_keyboard())


async def myid_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u:
        return
    await update.message.reply_text(f"Your user_id: {u.id}")


async def requestpremium_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if not u:
        return

    note = " ".join(context.args).strip()
    if not note:
        await update.message.reply_text(
            "Please include a note.\nExample:\n/requestpremium BMC receipt #XXXX",
            reply_markup=home_keyboard(),
        )
        return

    add_premium_request(u.id, note)
    add_log(u.id, "premium_request", note[:200])

    await update.message.reply_text(
        "✅ Premium request received.\n"
        "An admin will review it soon.\n\n"
        "Tip: include donation receipt ID or screenshot info.",
        reply_markup=home_keyboard(),
    )

    # notify admin (if configured)
    if ADMIN_ID and ADMIN_ID != 0:
        try:
            await context.bot.send_message(
                chat_id=ADMIN_ID,
                text=f"⭐ New premium request\nuser_id: {u.id}\n@{u.username}\nnote: {note}",
            )
        except Exception:
            pass


# === ADMIN COMMANDS ===
def is_admin(user_id: int) -> bool:
    return ADMIN_ID != 0 and user_id == ADMIN_ID


async def pending_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(u.id):
        return

    rows = list_pending_requests(limit=10)
    if not rows:
        await update.message.reply_text("No pending requests.")
        return

    text = "🧾 Pending premium requests (latest 10)\n\n"
    for rid, uid, ts, note in rows:
        text += f"#{rid} | user_id={uid} | {ts}\n{note}\n\n"
    text += "Use: /grant <user_id> <days>  (then optionally /markapproved <request_id>)"
    await update.message.reply_text(text)


async def grant_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(u.id):
        return

    if len(context.args) < 2:
        await update.message.reply_text("Usage: /grant <user_id> <days>")
        return

    try:
        target_id = int(context.args[0])
        days = int(context.args[1])
        if days <= 0:
            raise ValueError
    except Exception:
        await update.message.reply_text("Invalid args. Usage: /grant <user_id> <days>")
        return

    set_premium(target_id, days=days, granted_by=u.id)
    add_log(u.id, "admin_grant", f"{target_id} days={days}")

    await update.message.reply_text(f"✅ Granted premium to {target_id} for {days} day(s).")
    try:
        await context.bot.send_message(
            chat_id=target_id,
            text=f"⭐ Premium activated!\nDuration: {days} day(s)\nMax size: {PREMIUM_MAX_MB} MB",
        )
    except Exception:
        pass


async def revoke_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(u.id):
        return

    if len(context.args) < 1:
        await update.message.reply_text("Usage: /revoke <user_id>")
        return

    try:
        target_id = int(context.args[0])
    except Exception:
        await update.message.reply_text("Invalid user_id.")
        return

    revoke_premium(target_id)
    add_log(u.id, "admin_revoke", str(target_id))
    await update.message.reply_text(f"✅ Revoked premium from {target_id}.")


async def markapproved_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(u.id):
        return
    if len(context.args) < 1:
        await update.message.reply_text("Usage: /markapproved <request_id>")
        return
    try:
        rid = int(context.args[0])
    except Exception:
        await update.message.reply_text("Invalid request_id.")
        return
    mark_request(rid, "approved")
    await update.message.reply_text(f"✅ Marked request #{rid} as approved.")


async def markrejected_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if not u or not is_admin(u.id):
        return
    if len(context.args) < 1:
        await update.message.reply_text("Usage: /markrejected <request_id>")
        return
    try:
        rid = int(context.args[0])
    except Exception:
        await update.message.reply_text("Invalid request_id.")
        return
    mark_request(rid, "rejected")
    await update.message.reply_text(f"✅ Marked request #{rid} as rejected.")


# === CALLBACKS (buttons) ===
async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    u = update.effective_user
    user_id = u.id if u else None

    if query.data == CB_HELP:
        if user_id:
            add_log(user_id, "cb_help")
        await query.message.reply_text(help_text(), reply_markup=home_keyboard())

    elif query.data == CB_DONATE:
        if user_id:
            inc_donate_opened(user_id)
            add_log(user_id, "cb_donate", DONATE_URL)
        await query.message.reply_text(
            "☕ Support BrewTechLab\n\n"
            "Donate here, then request premium access:\n"
            "/requestpremium BMC receipt #XXXX",
            reply_markup=donate_url_keyboard(),
            disable_web_page_preview=True,
        )

    elif query.data == CB_PREMIUM:
        if not user_id:
            return
        add_log(user_id, "cb_premium")
        await query.message.reply_text(premium_text(user_id), reply_markup=home_keyboard())

    elif query.data == CB_STATS:
        if not user_id:
            return
        add_log(user_id, "cb_stats")
        stats = get_user_stats(user_id)
        if not stats:
            await query.message.reply_text("No stats yet.", reply_markup=home_keyboard())
            return
        msgs, files, donate = stats
        prem = "ACTIVE" if is_premium(user_id) else "NO"
        await query.message.reply_text(
            f"📊 Your stats\n\nMessages: {msgs}\nFiles sent: {files}\nDonate opens: {donate}\nPremium: {prem}",
            reply_markup=home_keyboard(),
        )


# === MESSAGE (download) ===
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    user_id = u.id if u else None
    if user_id:
        inc_messages(user_id)

    message_text = (update.message.text or "").strip()
    match = URL_RE.search(message_text)

    if not match:
        if user_id:
            add_log(user_id, "invalid_message", message_text[:200])
        await update.message.reply_text(
            "Please send a valid HTTP/HTTPS direct file URL.",
            reply_markup=home_keyboard(),
        )
        return

    url = match.group(1).rstrip(").,]}>\"'")

    if not is_valid_url(url):
        if user_id:
            add_log(user_id, "invalid_url", url[:300])
        await update.message.reply_text("Invalid or blocked URL.", reply_markup=home_keyboard())
        return

    max_bytes = allowed_max_bytes(user_id or 0)
    max_mb = PREMIUM_MAX_MB if is_premium(user_id or 0) else FREE_MAX_MB

    status = await update.message.reply_text(f"⬇️ Downloading file... (limit {max_mb} MB)")

    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://google.com/",
        }

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=40.0,
            headers=headers,
        ) as client:

            response = await client.get(url)

            if response.status_code == 403:
                if user_id:
                    add_log(user_id, "download_blocked_403", url[:500])
                await status.edit_text(
                    "❌ Download blocked (HTTP 403).\n"
                    "This website blocks automated downloads.\n"
                    "Try another direct file link source."
                )
                return

            if response.status_code == 401:
                if user_id:
                    add_log(user_id, "unauthorized_401", url[:500])
                await status.edit_text(
                    "❌ Unauthorized (HTTP 401).\n"
                    "This link likely requires login/cookies."
                )
                return

            if response.status_code >= 400:
                if user_id:
                    add_log(user_id, f"download_failed_{response.status_code}", url[:500])
                await status.edit_text(f"❌ Download failed (HTTP {response.status_code})")
                return

            content_disposition = response.headers.get("content-disposition")
            filename = extract_filename(url, content_disposition)

            temp_path = os.path.join(os.getcwd(), f"temp_{filename}")
            downloaded = 0

            with open(temp_path, "wb") as f:
                async for chunk in response.aiter_bytes(1024 * 128):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        f.close()
                        os.remove(temp_path)
                        if user_id:
                            add_log(user_id, "file_too_large", f"{downloaded} bytes | {url[:300]}")
                        await status.edit_text(
                            f"❌ File exceeded your limit ({max_mb} MB).\n"
                            "Tip: /premium"
                        )
                        return
                    f.write(chunk)

        await status.edit_text("📤 Uploading to Telegram...")

        await update.message.reply_document(
            document=open(temp_path, "rb"),
            filename=filename,
            caption=f"✅ Download complete ({downloaded/1024/1024:.1f} MB)\n{url}",
            reply_markup=donate_url_keyboard(),
        )

        if user_id:
            inc_files_sent(user_id)
            add_log(user_id, "file_sent", f"{filename} | {downloaded} bytes")

        os.remove(temp_path)
        await status.delete()

    except Exception as e:
        if user_id:
            add_log(user_id, "exception", str(e)[:500])
        await status.edit_text(f"⚠️ Error: {str(e)}")


# === APP ===
def main():
    if not TOKEN:
        raise RuntimeError("TOKEN is empty. Set environment variable TOKEN.")

    db_init()

    app = ApplicationBuilder().token(TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("donate", donate_cmd))
    app.add_handler(CommandHandler("premium", premium_cmd))
    app.add_handler(CommandHandler("stats", stats_cmd))
    app.add_handler(CommandHandler("myid", myid_cmd))
    app.add_handler(CommandHandler("requestpremium", requestpremium_cmd))

    # Admin commands
    app.add_handler(CommandHandler("pending", pending_cmd))
    app.add_handler(CommandHandler("grant", grant_cmd))
    app.add_handler(CommandHandler("revoke", revoke_cmd))
    app.add_handler(CommandHandler("markapproved", markapproved_cmd))
    app.add_handler(CommandHandler("markrejected", markrejected_cmd))

    # Buttons
    app.add_handler(CallbackQueryHandler(on_callback))

    # Messages
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()

import os
import re
import sqlite3
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
    CallbackQueryHandler,
)

# =========================
# === CONFIG (ENV VARS) ===
# =========================
TOKEN = os.getenv("TOKEN", "").strip()

DONATE_URL = "https://buymeacoffee.com/brewtechlab"
DONATE_TEXT = (
    "☕ Support BrewTechLab\n\n"
    "If this bot helps you, you can support the project here:"
)

DB_PATH = "brewtechlab_bot.db"

URL_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)

# Callback data
CB_HELP = "cb_help"
CB_DONATE = "cb_donate"
CB_STATS = "cb_stats"
CB_PREMIUM = "cb_premium"

# =========================
# === PREMIUM SETTINGS  ===
# =========================
# File size limits (MB) by tier
LIMIT_MB_FREE = 20
LIMIT_MB_STARTER = 30
LIMIT_MB_PRO = 45
LIMIT_MB_ULTRA = 45  # keep safe for Telegram bot upload limits

# Premium durations
TIER_DAYS = {
    "starter": 30,
    "pro": 90,
    "ultra": 365,
}


# =========================
# === DATABASE          ===
# =========================
def db_connect():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


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
            donate_opened INTEGER DEFAULT 0,
            premium_until TEXT,
            premium_tier TEXT
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
        INSERT INTO users (
            user_id, username, first_name, last_name,
            first_seen, last_seen,
            messages_count, files_sent, donate_opened,
            premium_until, premium_tier
        )
        VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, NULL, NULL)
        ON CONFLICT(user_id) DO UPDATE SET
            username=excluded.username,
            first_name=excluded.first_name,
            last_name=excluded.last_name,
            last_seen=excluded.last_seen
    """, (u.id, u.username, u.first_name, u.last_name, now, now))
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


def add_log(user_id: int | None, event: str, detail: str = ""):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO logs (ts, user_id, event, detail) VALUES (?, ?, ?, ?)",
        (now_utc(), user_id, event, detail),
    )
    con.commit()
    con.close()


def get_user_stats(user_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "SELECT messages_count, files_sent, donate_opened, premium_until, premium_tier FROM users WHERE user_id = ?",
        (user_id,),
    )
    row = cur.fetchone()
    con.close()
    return row


def is_premium_active(premium_until: str | None) -> bool:
    if not premium_until:
        return False
    try:
        dt = datetime.fromisoformat(premium_until)

        # nếu datetime không có timezone → gán UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt > datetime.now(timezone.utc)
    except Exception:
        return False


def format_expiry(dt_str: str | None) -> str:
    if not dt_str:
        return "-"
    try:
        dt = datetime.fromisoformat(dt_str)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return dt_str

def get_effective_limit_mb(user_id: int) -> int:
    row = get_user_stats(user_id)
    if not row:
        return LIMIT_MB_FREE

    premium_until = row[3]
    premium_tier = (row[4] or "").lower().strip()

    if not is_premium_active(premium_until):
        return LIMIT_MB_FREE

    if premium_tier == "starter":
        return LIMIT_MB_STARTER
    if premium_tier == "pro":
        return LIMIT_MB_PRO
    if premium_tier == "ultra":
        return LIMIT_MB_ULTRA
    return LIMIT_MB_STARTER


def grant_premium(user_id: int, tier: str, days: int):
    tier = tier.lower().strip()
    now = datetime.now(timezone.utc)

    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT premium_until FROM users WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    current_until = row[0] if row else None

    base = now
    if current_until and is_premium_active(current_until):
        try:
            base = datetime.fromisoformat(current_until)
        except Exception:
            base = now

    new_until = base + timedelta(days=days)

    cur.execute(
        "UPDATE users SET premium_until = ?, premium_tier = ?, last_seen = ? WHERE user_id = ?",
        (new_until.isoformat(), tier, now_utc(), user_id),
    )
    con.commit()
    con.close()


# =========================
# === HELPERS           ===
# =========================
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
            name = os.path.basename(match.group(1)).strip()
            return name or "download"

    path = urlparse(url).path
    name = os.path.basename(path) or "download"
    return name


def sanitize_filename(name: str) -> str:
    name = name.strip().replace("\x00", "")
    name = re.sub(r"[<>:\"/\\|?*\n\r\t]", "_", name)
    if len(name) > 120:
        base, ext = os.path.splitext(name)
        name = base[:100] + ext[:20]
    return name or "download"


def donate_url_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("☕ Buy Me a Coffee", url=DONATE_URL)]]
    )


def home_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("⬇️ How to use", callback_data=CB_HELP)],
            [InlineKeyboardButton("⭐ Premium", callback_data=CB_PREMIUM)],
            [InlineKeyboardButton("☕ Donate", callback_data=CB_DONATE)],
            [InlineKeyboardButton("📊 Stats", callback_data=CB_STATS)],
        ]
    )


def help_text(max_mb: int) -> str:
    return (
        "⬇️ How to use\n\n"
        "1) Send a DIRECT file link (mp4/mp3/pdf/jpg/zip...)\n"
        f"2) Max size (your tier): {max_mb} MB\n\n"
        "Notes:\n"
        "- Some websites block automated downloads (HTTP 403).\n"
        "- Links that require login/cookies may fail (HTTP 401).\n\n"
        "Commands:\n"
        "/start  /help  /donate  /stats\n\n"
        "Premium:\n"
        "/claim ⭐ Tier 1 — Starter\n"
        "/claim 🚀 TIER 2 — PRO\n"
        "/claim 👑 TIER 3 — ULTRA\n"
    )


def premium_text() -> str:
    return (
        "⭐ Premium Upgrade\n\n"
        "Limits:\n"
        "• Free max: 20 MB\n"
        "• Premium max: 50 MB\n\n"
        "Claim one of these tiers:\n\n"
        "/claim ⭐ Tier 1 — Starter  (30 days)\n"
        "/claim 🚀 TIER 2 — PRO      (90 days)\n"
        "/claim 👑 TIER 3 — ULTRA    (365 days)\n\n"
        f"Support project: {DONATE_URL}"
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    add_log(u.id if u else None, "start")

await update.message.reply_text(
    "👋 <b>Welcome to BrewTechLab Downloader!</b>\n\n"
    "Send me a DIRECT file link and I'll download + upload it back to you.\n\n"
    "📦 <b>Limits</b>\n"
    "• Free: 20 MB\n"
    "• Premium: 50 MB\n\n"
    "🚀 <b>Upgrade (claim)</b>\n\n"
    "/claim ⭐ Tier 1 - Starter\n"
    "/claim 🚀 TIER 2 - PRO\n"
    "/claim 👑 TIER 3 - ULTRA",
    reply_markup=home_keyboard(),
    parse_mode="HTML",
)

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    add_log(u.id if u else None, "help_command")

    max_mb = get_effective_limit_mb(u.id) if u else LIMIT_MB_FREE
    await update.message.reply_text(help_text(max_mb), reply_markup=home_keyboard())

async def donate_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if u:
        inc_donate_opened(u.id)
        add_log(u.id, "donate_command", DONATE_URL)

    await update.message.reply_text(
        DONATE_TEXT,
        reply_markup=donate_url_keyboard(),
        disable_web_page_preview=True,
    )


async def stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if not u:
        return

    row = get_user_stats(u.id)
    add_log(u.id, "stats_command")

    if not row:
        await update.message.reply_text("No stats yet.", reply_markup=home_keyboard())
        return

    msgs, files, donate, premium_until, premium_tier = row
    prem = "YES ✅" if is_premium_active(premium_until) else "NO ❌"
    until_line = f"\nUntil: {premium_until}" if is_premium_active(premium_until) else ""
    tier_line = f"\nTier: {str(premium_tier).upper()}" if is_premium_active(premium_until) else ""
    limit_mb = get_effective_limit_mb(u.id)

    await update.message.reply_text(
        "📊 Your stats\n\n"
        f"Messages: {int(msgs)}\n"
        f"Files sent: {int(files)}\n"
        f"Donate opens: {int(donate)}\n"
        f"Premium: {prem}{tier_line}{until_line}\n"
        f"Max file size: {limit_mb} MB",
        reply_markup=home_keyboard(),
    )


async def claim_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if not u:
        return

    inc_messages(u.id)

    text = (update.message.text or "").lower()

    # Match by tier keywords
    if ("starter" in text) or ("tier 1" in text):
        tier = "starter"
    elif ("pro" in text) or ("tier 2" in text):
        tier = "pro"
    elif ("ultra" in text) or ("tier 3" in text):
        tier = "ultra"
    else:
        await update.message.reply_text(
            "Usage:\n"
            "/claim ⭐ Tier 1 — Starter\n"
            "/claim 🚀 TIER 2 — PRO\n"
            "/claim 👑 TIER 3 — ULTRA",
            reply_markup=home_keyboard(),
        )
        return


    grant_premium(u.id, tier, TIER_DAYS[tier])
    add_log(u.id, "claim", tier)

    row = get_user_stats(u.id)
    premium_until = row[3] if row else None
    limit_mb = get_effective_limit_mb(u.id)

    await update.message.reply_text(
    "✅ Premium activated!\n"
    f"Tier: {tier.upper()}\n"
    f"Expires: {format_expiry(premium_until)}\n"
    f"Max file size: {limit_mb} MB",
    reply_markup=home_keyboard(),
)


# =========================
# === CALLBACKS         ===
# =========================
async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    u = update.effective_user
    user_id = u.id if u else None

    if query.data == CB_HELP:
        if user_id:
            add_log(user_id, "cb_help")
        max_mb = get_effective_limit_mb(user_id) if user_id else LIMIT_MB_FREE
        await query.message.reply_text(help_text(max_mb), reply_markup=home_keyboard())

    elif query.data == CB_PREMIUM:
        if user_id:
            add_log(user_id, "cb_premium")
        await query.message.reply_text(premium_text(), reply_markup=home_keyboard())

    elif query.data == CB_DONATE:
        if user_id:
            inc_donate_opened(user_id)
            add_log(user_id, "cb_donate", DONATE_URL)
        await query.message.reply_text(
            DONATE_TEXT,
            reply_markup=donate_url_keyboard(),
            disable_web_page_preview=True,
        )

    elif query.data == CB_STATS:
        if not user_id:
            return
        add_log(user_id, "cb_stats")
        row = get_user_stats(user_id)
        if not row:
            await query.message.reply_text("No stats yet.", reply_markup=home_keyboard())
            return

        msgs, files, donate, premium_until, premium_tier = row
        prem = "YES ✅" if is_premium_active(premium_until) else "NO ❌"
        until_line = f"\nUntil: {premium_until}" if is_premium_active(premium_until) else ""
        tier_line = f"\nTier: {str(premium_tier).upper()}" if is_premium_active(premium_until) else ""
        limit_mb = get_effective_limit_mb(user_id)

        await query.message.reply_text(
            "📊 Your stats\n\n"
            f"Messages: {int(msgs)}\n"
            f"Files sent: {int(files)}\n"
            f"Donate opens: {int(donate)}\n"
            f"Premium: {prem}{tier_line}{until_line}\n"
            f"Max file size: {limit_mb} MB",
            reply_markup=home_keyboard(),
        )


# =========================
# === MESSAGE (DOWNLOAD) ===
# =========================
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

    # premium-aware limits
    limit_mb = get_effective_limit_mb(user_id) if user_id else LIMIT_MB_FREE
    max_bytes = int(limit_mb * 1024 * 1024)

    status = await update.message.reply_text("⬇️ Downloading file...")

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
            timeout=60.0,
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
            filename = sanitize_filename(extract_filename(url, content_disposition))

            # unique temp file
            suffix = os.path.splitext(filename)[1]
            tmp_name = f"bt_{uuid.uuid4().hex}{suffix}"
            temp_path = os.path.join(tempfile.gettempdir(), tmp_name)

            downloaded = 0
            with open(temp_path, "wb") as f:
                async for chunk in response.aiter_bytes(1024 * 128):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        f.close()
                        try:
                            os.remove(temp_path)
                        except Exception:
                            pass
                        if user_id:
                            add_log(user_id, "file_too_large", f"{downloaded} bytes | {url[:300]}")
                        await status.edit_text(f"❌ File exceeded max size ({limit_mb} MB).")
                        return
                    f.write(chunk)

        await status.edit_text("📤 Uploading to Telegram...")

        with open(temp_path, "rb") as fp:
            await update.message.reply_document(
                document=fp,
                filename=filename,
                caption=f"✅ Download complete ({downloaded/1024/1024:.1f} MB)\n{url}",
                reply_markup=donate_url_keyboard(),
            )

        if user_id:
            inc_files_sent(user_id)
            add_log(user_id, "file_sent", f"{filename} | {downloaded} bytes")

        try:
            os.remove(temp_path)
        except Exception:
            pass

        await status.delete()

    except Exception as e:
        if user_id:
            add_log(user_id, "exception", str(e)[:500])
        await status.edit_text(f"⚠️ Error: {str(e)}")


# =========================
# === APP              ===
# =========================
def main():
    if not TOKEN:
        raise RuntimeError("Missing TOKEN env var. Set TOKEN in Railway Variables.")

    db_init()

    app = ApplicationBuilder().token(TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("donate", donate_cmd))
    app.add_handler(CommandHandler("stats", stats_cmd))
    app.add_handler(CommandHandler("claim", claim_cmd))

    # Buttons
    app.add_handler(CallbackQueryHandler(on_callback))

    # Messages
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("Bot is running...")
    app.run_polling(close_loop=False)


if __name__ == "__main__":
    main()

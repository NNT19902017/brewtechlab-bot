import os
import re
import sqlite3
import tempfile
from datetime import datetime, timedelta, UTC
from urllib.parse import urlparse

import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

# =========================
# === CONFIG (ENV VARS) ===
# =========================
# Railway: set TOKEN in Variables
TOKEN = os.getenv("TOKEN", "").strip()

DONATE_URL = os.getenv("DONATE_URL", "https://buymeacoffee.com/brewtechlab").strip()

# Limits
LIMIT_MB_FREE = int(os.getenv("LIMIT_MB_FREE", "20"))
LIMIT_MB_PREMIUM = int(os.getenv("LIMIT_MB_PREMIUM", "50"))

# Optional: set INSECURE_SSL=1 only if you keep getting SSL verify errors
INSECURE_SSL = os.getenv("INSECURE_SSL", "0").strip() == "1"

DB_PATH = os.getenv("DB_PATH", "brewtechlab_bot.db").strip()

# HTTP
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "60"))
CHUNK_SIZE = 1024 * 128  # 128KB

URL_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)

# Callback data
CB_HELP = "cb_help"
CB_PREMIUM = "cb_premium"
CB_DONATE = "cb_donate"
CB_STATS = "cb_stats"

# Premium tiers
TIER_DAYS = {"starter": 30, "pro": 90, "ultra": 365}
TIER_LABEL = {
    "starter": "⭐ Tier 1 — Starter",
    "pro": "🚀 TIER 2 — PRO",
    "ultra": "👑 TIER 3 — ULTRA",
}


# =========================
# === TIME HELPERS     ===
# =========================
def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def parse_dt_utc(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except Exception:
        return None


def is_premium_active(premium_until: str | None) -> bool:
    dt = parse_dt_utc(premium_until)
    if not dt:
        return False
    return dt > datetime.now(UTC)


def format_expiry(dt_str: str | None) -> str:
    dt = parse_dt_utc(dt_str)
    if not dt:
        return "-"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


# =========================
# === DB               ===
# =========================
def db_connect():
    return sqlite3.connect(DB_PATH)


def db_init():
    con = db_connect()
    cur = con.cursor()

    cur.execute(
        """
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
            premium_tier TEXT DEFAULT ''
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            user_id INTEGER,
            event TEXT,
            detail TEXT
        )
        """
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


def upsert_user(update: Update):
    u = update.effective_user
    if not u:
        return
    now = now_utc()

    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO users (user_id, username, first_name, last_name, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            username=excluded.username,
            first_name=excluded.first_name,
            last_name=excluded.last_name,
            last_seen=excluded.last_seen
        """,
        (u.id, u.username, u.first_name, u.last_name, now, now),
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


def get_user_row(user_id: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute(
        """
        SELECT messages_count, files_sent, donate_opened, premium_until, premium_tier
        FROM users WHERE user_id = ?
        """,
        (user_id,),
    )
    row = cur.fetchone()
    con.close()
    return row


def grant_premium(user_id: int, tier: str, days: int, source: str = "claim"):
    until_dt = datetime.now(UTC) + timedelta(days=days)
    premium_until = until_dt.isoformat()

    con = db_connect()
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET premium_until = ?, premium_tier = ?, last_seen = ? WHERE user_id = ?",
        (premium_until, tier, now_utc(), user_id),
    )
    con.commit()
    con.close()

    add_log(user_id, "grant_premium", f"{tier}|{days}|{source}|{premium_until}")


def get_effective_limit_mb(user_id: int) -> int:
    row = get_user_row(user_id)
    if not row:
        return LIMIT_MB_FREE
    premium_until = row[3]
    return LIMIT_MB_PREMIUM if is_premium_active(premium_until) else LIMIT_MB_FREE


# =========================
# === UI TEXT          ===
# =========================
def home_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("⬇️ How to use", callback_data=CB_HELP)],
            [InlineKeyboardButton("⭐ Premium", callback_data=CB_PREMIUM)],
            [InlineKeyboardButton("☕ Donate", callback_data=CB_DONATE)],
            [InlineKeyboardButton("📊 Stats", callback_data=CB_STATS)],
        ]
    )


def donate_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("☕ Buy Me a Coffee", url=DONATE_URL)]])


def premium_text() -> str:
    return (
        "⭐ <b>Premium Upgrade</b>\n\n"
        "<b>Limits</b>:\n"
        f"• Free max: <b>{LIMIT_MB_FREE} MB</b>\n"
        f"• Premium max: <b>{LIMIT_MB_PREMIUM} MB</b>\n\n"
        "<b>Claim commands</b>:\n"
        f"/claim ⭐ Tier 1 — Starter  (<b>{TIER_DAYS['starter']} days</b>)\n"
        f"/claim 🚀 TIER 2 — PRO      (<b>{TIER_DAYS['pro']} days</b>)\n"
        f"/claim 👑 TIER 3 — ULTRA    (<b>{TIER_DAYS['ultra']} days</b>)\n\n"
        f"Support: {DONATE_URL}"
    )


def help_text(max_mb: int) -> str:
    return (
        "⬇️ <b>How to use</b>\n\n"
        "1) Send a <b>DIRECT</b> file link (mp4/mp3/pdf/jpg/zip...)\n"
        f"2) Your current max size: <b>{max_mb} MB</b>\n\n"
        "<b>Notes</b>:\n"
        "• Some websites block bots (HTTP 403)\n"
        "• Links that require login may fail (HTTP 401)\n\n"
        "<b>Commands</b>:\n"
        "/start /help /premium /donate /stats\n"
        "/claim ⭐ starter | 🚀 pro | 👑 ultra"
    )


def start_text() -> str:
    return (
        "👋 <b>Welcome to BrewTechLab Downloader!</b>\n\n"
        "Send me a <b>DIRECT</b> file link and I'll download + upload it back to you.\n\n"
        "📦 <b>Limits</b>\n"
        f"• Free: <b>{LIMIT_MB_FREE} MB</b>\n"
        f"• Premium: <b>{LIMIT_MB_PREMIUM} MB</b>\n\n"
        "🚀 <b>Upgrade (claim)</b>\n"
        "/claim ⭐ Tier 1 — Starter\n"
        "/claim 🚀 TIER 2 — PRO\n"
        "/claim 👑 TIER 3 — ULTRA"
    )


# =========================
# === COMMANDS          ===
# =========================
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    add_log(u.id if u else None, "start")
    await update.message.reply_text(start_text(), reply_markup=home_keyboard(), parse_mode=ParseMode.HTML)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    add_log(u.id if u else None, "help")
    max_mb = get_effective_limit_mb(u.id) if u else LIMIT_MB_FREE
    await update.message.reply_text(help_text(max_mb), reply_markup=home_keyboard(), parse_mode=ParseMode.HTML)


async def cmd_premium(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    add_log(u.id if u else None, "premium")
    await update.message.reply_text(premium_text(), reply_markup=home_keyboard(), parse_mode=ParseMode.HTML)


async def cmd_donate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if u:
        inc_donate_opened(u.id)
        add_log(u.id, "donate_open", DONATE_URL)
    await update.message.reply_text(
        "☕ <b>Support BrewTechLab</b>\n\nIf this bot helps you, you can support the project here:",
        reply_markup=donate_keyboard(),
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if not u:
        return

    row = get_user_row(u.id)
    add_log(u.id, "stats")
    if not row:
        await update.message.reply_text("No stats yet.", reply_markup=home_keyboard())
        return

    msgs, files, donate, premium_until, premium_tier = row
    premium_on = is_premium_active(premium_until)
    tier_label = TIER_LABEL.get((premium_tier or "").lower(), (premium_tier or "").upper() or "-")
    expiry = format_expiry(premium_until)
    limit_mb = get_effective_limit_mb(u.id)

    await update.message.reply_text(
        "📊 <b>Your stats</b>\n\n"
        f"Messages: <b>{int(msgs)}</b>\n"
        f"Files sent: <b>{int(files)}</b>\n"
        f"Donate opens: <b>{int(donate)}</b>\n"
        f"Premium: <b>{'YES' if premium_on else 'NO'}</b>\n"
        f"Tier: <b>{tier_label}</b>\n"
        f"Expires: <b>{expiry}</b>\n"
        f"Max file size now: <b>{limit_mb} MB</b>",
        reply_markup=home_keyboard(),
        parse_mode=ParseMode.HTML,
    )


async def cmd_claim(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    if not u:
        return
    inc_messages(u.id)

    raw = (update.message.text or "").strip()
    text = raw.lower()

    # Match by keywords or tier numbers/emojis
    tier = None
    if ("starter" in text) or ("tier 1" in text) or ("⭐" in raw):
        tier = "starter"
    elif ("pro" in text) or ("tier 2" in text) or ("🚀" in raw):
        tier = "pro"
    elif ("ultra" in text) or ("tier 3" in text) or ("👑" in raw):
        tier = "ultra"

    if not tier:
        await update.message.reply_text(
            "Usage:\n"
            "/claim ⭐ Tier 1 — Starter\n"
            "/claim 🚀 TIER 2 — PRO\n"
            "/claim 👑 TIER 3 — ULTRA",
            reply_markup=home_keyboard(),
        )
        return

    grant_premium(u.id, tier, TIER_DAYS[tier], source="claim")
    row = get_user_row(u.id)
    premium_until = row[3] if row else None
    limit_mb = get_effective_limit_mb(u.id)

    await update.message.reply_text(
        "✅ <b>Premium activated!</b>\n"
        f"Tier: <b>{tier.upper()}</b>\n"
        f"Expires: <b>{format_expiry(premium_until)}</b>\n"
        f"Max file size: <b>{limit_mb} MB</b>",
        reply_markup=home_keyboard(),
        parse_mode=ParseMode.HTML,
    )


# =========================
# === CALLBACKS         ===
# =========================
async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()

    u = update.effective_user
    user_id = u.id if u else None

    if q.data == CB_HELP:
        if user_id:
            add_log(user_id, "cb_help")
        max_mb = get_effective_limit_mb(user_id) if user_id else LIMIT_MB_FREE
        await q.message.reply_text(help_text(max_mb), reply_markup=home_keyboard(), parse_mode=ParseMode.HTML)

    elif q.data == CB_PREMIUM:
        if user_id:
            add_log(user_id, "cb_premium")
        await q.message.reply_text(premium_text(), reply_markup=home_keyboard(), parse_mode=ParseMode.HTML)

    elif q.data == CB_DONATE:
        if user_id:
            inc_donate_opened(user_id)
            add_log(user_id, "cb_donate", DONATE_URL)
        await q.message.reply_text(
            "☕ <b>Support BrewTechLab</b>\n\nIf this bot helps you, you can support the project here:",
            reply_markup=donate_keyboard(),
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

    elif q.data == CB_STATS:
        if not user_id:
            return
        add_log(user_id, "cb_stats")
        # reuse stats cmd logic
        row = get_user_row(user_id)
        if not row:
            await q.message.reply_text("No stats yet.", reply_markup=home_keyboard())
            return
        msgs, files, donate, premium_until, premium_tier = row
        premium_on = is_premium_active(premium_until)
        tier_label = TIER_LABEL.get((premium_tier or "").lower(), (premium_tier or "").upper() or "-")
        expiry = format_expiry(premium_until)
        limit_mb = get_effective_limit_mb(user_id)

        await q.message.reply_text(
            "📊 <b>Your stats</b>\n\n"
            f"Messages: <b>{int(msgs)}</b>\n"
            f"Files sent: <b>{int(files)}</b>\n"
            f"Donate opens: <b>{int(donate)}</b>\n"
            f"Premium: <b>{'YES' if premium_on else 'NO'}</b>\n"
            f"Tier: <b>{tier_label}</b>\n"
            f"Expires: <b>{expiry}</b>\n"
            f"Max file size now: <b>{limit_mb} MB</b>",
            reply_markup=home_keyboard(),
            parse_mode=ParseMode.HTML,
        )


# =========================
# === DOWNLOAD MESSAGE  ===
# =========================
def is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = (p.hostname or "").lower()
        if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
            return False
        return True
    except Exception:
        return False


def sanitize_url(url: str) -> str:
    return url.rstrip(").,]}>\"'")


def extract_filename(url: str, content_disposition: str | None) -> str:
    if content_disposition:
        m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', content_disposition, re.IGNORECASE)
        if m:
            name = os.path.basename(m.group(1)).strip()
            if name:
                return name
    path = urlparse(url).path
    name = os.path.basename(path) or "download"
    return name


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upsert_user(update)
    u = update.effective_user
    user_id = u.id if u else None
    if user_id:
        inc_messages(user_id)

    message_text = (update.message.text or "").strip()
    m = URL_RE.search(message_text)
    if not m:
        if user_id:
            add_log(user_id, "invalid_message", message_text[:200])
        await update.message.reply_text(
            "Please send a valid HTTP/HTTPS direct file URL.",
            reply_markup=home_keyboard(),
        )
        return

    url = sanitize_url(m.group(1))
    if not is_valid_url(url):
        if user_id:
            add_log(user_id, "invalid_url", url[:300])
        await update.message.reply_text("Invalid or blocked URL.", reply_markup=home_keyboard())
        return

    limit_mb = get_effective_limit_mb(user_id) if user_id else LIMIT_MB_FREE
    max_bytes = limit_mb * 1024 * 1024

    status = await update.message.reply_text("⬇️ Downloading file...")

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

    verify = False if INSECURE_SSL else True

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=HTTP_TIMEOUT,
            headers=headers,
            verify=verify,
        ) as client:
            # Try HEAD first to detect size early (may be blocked)
            try:
                head = await client.head(url)
                if head.status_code < 400:
                    cl = head.headers.get("content-length")
                    if cl and cl.isdigit() and int(cl) > max_bytes:
                        if user_id:
                            add_log(user_id, "file_too_large_head", f"{cl} bytes | {url[:300]}")
                        await status.edit_text(f"❌ File too large. Max allowed: {limit_mb} MB.")
                        return
            except Exception:
                pass

            r = await client.get(url)
            if r.status_code == 403:
                if user_id:
                    add_log(user_id, "download_blocked_403", url[:500])
                await status.edit_text(
                    "❌ Download blocked (HTTP 403).\nThis website blocks automated downloads.\nTry another direct file link."
                )
                return
            if r.status_code == 401:
                if user_id:
                    add_log(user_id, "unauthorized_401", url[:500])
                await status.edit_text("❌ Unauthorized (HTTP 401).\nThis link likely requires login/cookies.")
                return
            if r.status_code == 404:
                if user_id:
                    add_log(user_id, "not_found_404", url[:500])
                await status.edit_text("❌ Not found (HTTP 404). Please check the link.")
                return
            if r.status_code >= 400:
                if user_id:
                    add_log(user_id, f"download_failed_{r.status_code}", url[:500])
                await status.edit_text(f"❌ Download failed (HTTP {r.status_code}).")
                return

            filename = extract_filename(url, r.headers.get("content-disposition"))
            downloaded = 0

            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                temp_path = tmp.name

            try:
                with open(temp_path, "wb") as f:
                    async for chunk in r.aiter_bytes(CHUNK_SIZE):
                        if not chunk:
                            continue
                        downloaded += len(chunk)
                        if downloaded > max_bytes:
                            if user_id:
                                add_log(user_id, "file_too_large_stream", f"{downloaded} bytes | {url[:300]}")
                            await status.edit_text(f"❌ File exceeded max size ({limit_mb} MB).")
                            return
                        f.write(chunk)

                await status.edit_text("📤 Uploading to Telegram...")
                with open(temp_path, "rb") as f:
                    await update.message.reply_document(
                        document=f,
                        filename=filename,
                        caption=f"✅ Done ({downloaded/1024/1024:.1f} MB)\n{url}",
                        reply_markup=donate_keyboard(),
                    )

                if user_id:
                    inc_files_sent(user_id)
                    add_log(user_id, "file_sent", f"{filename} | {downloaded} bytes")

                await status.delete()

            finally:
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    except httpx.ConnectError as e:
        if user_id:
            add_log(user_id, "httpx_connect_error", str(e)[:500])
        await status.edit_text("⚠️ Connection error. Try another link.")
    except httpx.HTTPError as e:
        if user_id:
            add_log(user_id, "httpx_error", str(e)[:500])
        await status.edit_text(f"⚠️ HTTP error: {str(e)}")
    except Exception as e:
        if user_id:
            add_log(user_id, "exception", str(e)[:500])
        await status.edit_text(f"⚠️ Error: {str(e)}")


# =========================
# === MAIN             ===
# =========================
def main():
    if not TOKEN:
        raise RuntimeError("Missing TOKEN env var. Set TOKEN in Railway Variables.")

    db_init()

    app = ApplicationBuilder().token(TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("premium", cmd_premium))
    app.add_handler(CommandHandler("donate", cmd_donate))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("claim", cmd_claim))

    # Buttons
    app.add_handler(CallbackQueryHandler(on_callback))

    # Messages (URLs)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()

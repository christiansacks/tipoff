import asyncio, re, smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def _strip_html(html: str) -> str:
    text = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
    text = re.sub(r"</p>|</tr>|</div>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


async def send_email(cfg: dict, to: str, subject: str, html: str, text: str = "") -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_sync, cfg, to, subject, html, text)


def _send_sync(cfg: dict, to: str, subject: str, html: str, text: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = cfg["from_addr"]
    msg["To"]      = to
    # plain must come first — clients prefer the last matching part
    msg.attach(MIMEText(text or _strip_html(html), "plain"))
    msg.attach(MIMEText(html, "html"))

    host = cfg["host"]
    port = int(cfg.get("port", 587))
    user = cfg.get("user", "")
    pwd  = cfg.get("password", "")
    tls  = cfg.get("tls", "starttls")

    if tls == "ssl":
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=ctx) as srv:
            if user:
                srv.login(user, pwd)
            srv.sendmail(cfg["from_addr"], [to], msg.as_string())
    elif tls == "starttls":
        with smtplib.SMTP(host, port, timeout=15) as srv:
            srv.ehlo()
            srv.starttls(context=ssl.create_default_context())
            srv.ehlo()
            if user:
                srv.login(user, pwd)
            srv.sendmail(cfg["from_addr"], [to], msg.as_string())
    else:  # none
        with smtplib.SMTP(host, port, timeout=15) as srv:
            if user:
                srv.login(user, pwd)
            srv.sendmail(cfg["from_addr"], [to], msg.as_string())

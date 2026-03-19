from __future__ import annotations

import html
import json
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "lab.db"
STYLE_PATH = BASE_DIR / "static" / "style.css"

PROBLEMS: list[dict[str, str | int]] = [
    {"area": "정찰(Recon)", "title": "열린 서비스 찾기", "description": "대상 10.10.10.20에서 열려있는 TCP 포트를 식별하세요.", "points": 50, "flag": "FLAG{recon_open_ports}"},
    {"area": "정찰(Recon)", "title": "서비스 버전 식별", "description": "웹서버와 SSH 버전을 정확히 식별해 제출하세요.", "points": 50, "flag": "FLAG{recon_service_version}"},
    {"area": "정찰(Recon)", "title": "숨겨진 디렉터리", "description": "웹 루트 하위의 관리자 경로를 탐색해 플래그 파일을 찾으세요.", "points": 70, "flag": "FLAG{recon_hidden_path}"},
    {"area": "웹 공격(Web)", "title": "SQL 인젝션 - 로그인 우회", "description": "취약한 로그인 폼에서 인증을 우회해 관리자 페이지에 접근하세요.", "points": 80, "flag": "FLAG{web_sql_login_bypass}"},
    {"area": "웹 공격(Web)", "title": "SQL 인젝션 - 데이터 추출", "description": "사용자 테이블에서 admin 계정의 해시값을 추출하세요.", "points": 90, "flag": "FLAG{web_sql_data_dump}"},
    {"area": "웹 공격(Web)", "title": "XSS 세션 탈취", "description": "저장형 XSS를 이용해 관리자 쿠키를 획득하세요.", "points": 90, "flag": "FLAG{web_stored_xss_cookie}"},
    {"area": "인증/권한(Auth)", "title": "약한 비밀번호 크래킹", "description": "제공된 해시 파일에서 사용자 비밀번호 1개를 복구하세요.", "points": 70, "flag": "FLAG{auth_weak_password}"},
    {"area": "인증/권한(Auth)", "title": "JWT 위변조", "description": "취약한 JWT 검증을 악용해 admin 권한 토큰을 생성하세요.", "points": 100, "flag": "FLAG{auth_jwt_forge}"},
    {"area": "인증/권한(Auth)", "title": "권한상승 sudo", "description": "취약한 sudoers 설정을 이용해 root 쉘을 획득하세요.", "points": 110, "flag": "FLAG{auth_sudo_privesc}"},
    {"area": "네트워크(Network)", "title": "평문 자격증명", "description": "캡처 파일에서 평문으로 전송된 계정 정보를 추출하세요.", "points": 60, "flag": "FLAG{net_plain_credentials}"},
    {"area": "네트워크(Network)", "title": "DNS 터널링 흔적", "description": "비정상 DNS 쿼리 패턴을 찾아 C2 도메인을 식별하세요.", "points": 80, "flag": "FLAG{net_dns_tunnel}"},
    {"area": "네트워크(Network)", "title": "MITM 탐지", "description": "ARP 스푸핑이 발생한 증거(공격자 MAC)를 찾으세요.", "points": 90, "flag": "FLAG{net_mitm_detected}"},
    {"area": "악성코드 분석(Malware)", "title": "의심 스크립트 IOC", "description": "샘플 스크립트에서 C2 URL을 추출하세요.", "points": 80, "flag": "FLAG{mal_ioc_c2_url}"},
    {"area": "악성코드 분석(Malware)", "title": "난독화 해제", "description": "난독화된 PowerShell에서 실행 명령의 원문을 복구하세요.", "points": 100, "flag": "FLAG{mal_deobfuscation}"},
    {"area": "악성코드 분석(Malware)", "title": "지속성 기법 식별", "description": "샘플에서 사용된 지속성(Persistence) 기법을 확인하세요.", "points": 90, "flag": "FLAG{mal_persistence_technique}"},
    {"area": "사고대응(IR)", "title": "침해 시작 시각", "description": "로그를 분석해 최초 침해 시각(UTC)을 제출하세요.", "points": 70, "flag": "FLAG{ir_initial_compromise_time}"},
    {"area": "사고대응(IR)", "title": "침해 경로 타임라인", "description": "웹셸 업로드부터 권한상승까지 핵심 단계 3개를 정리하세요.", "points": 90, "flag": "FLAG{ir_attack_timeline}"},
    {"area": "사고대응(IR)", "title": "영향 범위 식별", "description": "유출된 데이터셋 이름과 건수를 찾아 제출하세요.", "points": 100, "flag": "FLAG{ir_impact_scope}"},
    {"area": "방어/하드닝(Defense)", "title": "WAF 룰 작성", "description": "SQLi 패턴을 차단하는 기본 룰을 적용하고 테스트하세요.", "points": 80, "flag": "FLAG{def_waf_rule_applied}"},
    {"area": "방어/하드닝(Defense)", "title": "로그인 보호", "description": "무차별 대입 공격 방지를 위한 지연/잠금 정책을 적용하세요.", "points": 80, "flag": "FLAG{def_bruteforce_blocked}"},
    {"area": "방어/하드닝(Defense)", "title": "시크릿 관리", "description": "코드 내 하드코딩된 API 키를 안전한 방식으로 교체하세요.", "points": 90, "flag": "FLAG{def_secret_rotation}"},
]


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE,
            organization TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            area TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            points INTEGER NOT NULL,
            flag TEXT NOT NULL
        );
        """
    )
    conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES ('threshold', '20')")
    conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES ('started', '0')")
    if conn.execute("SELECT COUNT(*) FROM challenges").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO challenges(area, title, description, points, flag) VALUES (:area, :title, :description, :points, :flag)",
            PROBLEMS,
        )
    conn.commit()
    conn.close()


def get_setting(key: str, default: str) -> str:
    conn = get_conn()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default


def set_setting(key: str, value: str) -> None:
    conn = get_conn()
    conn.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    conn.commit()
    conn.close()


def participant_count() -> int:
    conn = get_conn()
    count = conn.execute("SELECT COUNT(*) FROM participants").fetchone()[0]
    conn.close()
    return count


def ensure_started() -> bool:
    threshold = int(get_setting("threshold", "20"))
    started = get_setting("started", "0") == "1"
    if not started and participant_count() >= threshold:
        set_setting("started", "1")
        started = True
    return started


def parse_post(environ: dict) -> dict[str, str]:
    size = int(environ.get("CONTENT_LENGTH") or 0)
    raw = environ["wsgi.input"].read(size).decode("utf-8")
    return {k: v[0] for k, v in parse_qs(raw).items()}


def html_page(title: str, body: str) -> bytes:
    template = f"""<!doctype html>
<html lang=\"ko\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{html.escape(title)}</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head>
<body><header><h1><a href=\"/\">AI Hacking Lab Workshop</a></h1>
<nav><a href=\"/register\">등록</a><a href=\"/challenges\">문제</a><a href=\"/admin\">운영자</a></nav></header>
<main>{body}</main></body></html>"""
    return template.encode("utf-8")


def response(start_response, status: str, body: bytes, content_type: str = "text/html; charset=utf-8"):
    start_response(status, [("Content-Type", content_type), ("Content-Length", str(len(body)))])
    return [body]


def redirect(start_response, location: str):
    start_response("302 Found", [("Location", location), ("Content-Length", "0")])
    return [b""]


def app(environ, start_response):
    init_db()
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    if method == "HEAD":
        method = "GET"

    if path == "/static/style.css":
        css = STYLE_PATH.read_bytes() if STYLE_PATH.exists() else b""
        return response(start_response, "200 OK", css, "text/css; charset=utf-8")

    if path == "/":
        threshold = int(get_setting("threshold", "20"))
        started = ensure_started()
        current = participant_count()
        host = environ.get("HTTP_HOST", "localhost:5000")
        register_url = f"http://{host}/register"
        qr_image = f"https://quickchart.io/qr?size=280&text={register_url}"
        body = f"""
<section class='card'><h2>공격/방어 실습 워크숍</h2>
<p>QR 등록 후 임계치 도달 시 자동 시작됩니다.</p>
<ul><li>현재 등록: <strong>{current}명</strong></li><li>시작 기준: <strong>{threshold}명</strong></li><li>상태: <strong>{'진행중' if started else '대기중'}</strong></li></ul></section>
<section class='grid'><div class='card'><h3>등록 QR</h3><img class='qr' src='{qr_image}' alt='QR'><p><a href='{register_url}'>직접 등록 링크 열기</a></p></div>
<div class='card'><h3>안내</h3><ol><li>QR 스캔</li><li>대기열 자동 집계</li><li>20명 내외 도달 시 자동 시작</li></ol></div></section>"""
        return response(start_response, "200 OK", html_page("워크숍 대기실", body))

    if path == "/register" and method == "GET":
        body = """
<section class='card narrow'><h2>워크숍 등록</h2>
<form method='post'><label>이름* <input type='text' name='name' required></label>
<label>이메일 <input type='email' name='email'></label><label>소속 <input type='text' name='organization'></label>
<button type='submit'>등록하고 대기실로 이동</button></form></section>"""
        return response(start_response, "200 OK", html_page("참가 등록", body))

    if path == "/register" and method == "POST":
        form = parse_post(environ)
        name = form.get("name", "").strip()
        email = form.get("email", "").strip().lower() or None
        organization = form.get("organization", "").strip()
        if not name:
            return response(start_response, "400 Bad Request", html_page("등록 오류", "<section class='card'><p>이름은 필수입니다.</p></section>"))

        token = secrets.token_urlsafe(12)
        conn = get_conn()
        try:
            conn.execute("INSERT INTO participants(token, name, email, organization) VALUES (?, ?, ?, ?)", (token, name, email, organization))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return response(start_response, "400 Bad Request", html_page("등록 오류", "<section class='card'><p>이미 등록된 이메일입니다.</p></section>"))
        conn.close()
        return redirect(start_response, f"/waiting/{token}")

    if path.startswith("/waiting/"):
        token = path.split("/waiting/", 1)[1]
        conn = get_conn()
        row = conn.execute("SELECT name FROM participants WHERE token = ?", (token,)).fetchone()
        conn.close()
        if not row:
            return redirect(start_response, "/register")
        name = html.escape(row[0])
        body = f"""
<section class='card narrow'><h2>{name}님, 등록 완료!</h2><p>시작 인원이 차면 자동 이동합니다.</p>
<p id='status'>대기 상태 확인 중...</p><progress id='progress' value='0' max='100'></progress></section>
<script>
const token='{token}';const s=document.getElementById('status');const p=document.getElementById('progress');
async function poll(){{const r=await fetch('/api/status/'+token);const d=await r.json();if(d.error){{s.textContent='등록 정보 없음';return;}}
const per=Math.min(100,Math.floor((d.current/d.threshold)*100));p.value=per;s.textContent=`현재 ${{d.current}} / ${{d.threshold}}명 등록 (${{per}}%)`;
if(d.started){{window.location.href=d.start_url;return;}}setTimeout(poll,3000);}}
poll();
</script>"""
        return response(start_response, "200 OK", html_page("대기실", body))

    if path.startswith("/api/status/"):
        token = path.split("/api/status/", 1)[1]
        conn = get_conn()
        exists = conn.execute("SELECT 1 FROM participants WHERE token = ?", (token,)).fetchone()
        conn.close()
        if not exists:
            data = json.dumps({"error": "not_found"}).encode("utf-8")
            return response(start_response, "404 Not Found", data, "application/json; charset=utf-8")
        data = json.dumps({
            "started": ensure_started(),
            "threshold": int(get_setting("threshold", "20")),
            "current": participant_count(),
            "start_url": "/challenges",
        }).encode("utf-8")
        return response(start_response, "200 OK", data, "application/json; charset=utf-8")

    if path == "/challenges":
        if not ensure_started():
            return redirect(start_response, "/")
        conn = get_conn()
        rows = conn.execute("SELECT area, title, description, points FROM challenges ORDER BY area, id").fetchall()
        conn.close()
        grouped: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            grouped.setdefault(row[0], []).append(row)
        chunks = ["<section class='card'><h2>실습 문제 목록 (총 21문제)</h2><p>각 영역별 3문제로 구성.</p></section>"]
        for area, items in grouped.items():
            chunks.append(f"<section class='card'><h3>{html.escape(area)}</h3><div class='challenge-list'>")
            for item in items:
                chunks.append(
                    f"<article class='challenge-item'><h4>{html.escape(item[1])} <span>{item[3]}점</span></h4><p>{html.escape(item[2])}</p></article>"
                )
            chunks.append("</div></section>")
        return response(start_response, "200 OK", html_page("실습 문제", "".join(chunks)))

    if path == "/admin" and method == "POST":
        form = parse_post(environ)
        action = form.get("action", "")
        if action == "set_threshold":
            threshold = max(1, int(form.get("threshold", "20")))
            set_setting("threshold", str(threshold))
        elif action == "start_now":
            set_setting("started", "1")
        elif action == "reset":
            set_setting("started", "0")
            conn = get_conn()
            conn.execute("DELETE FROM participants")
            conn.commit()
            conn.close()
        return redirect(start_response, "/admin")

    if path == "/admin":
        started = get_setting("started", "0") == "1"
        threshold = int(get_setting("threshold", "20"))
        current = participant_count()
        body = f"""
<section class='card'><h2>운영자 제어판</h2><p>현재 등록: <strong>{current}명</strong> / 시작 기준: <strong>{threshold}명</strong></p>
<p>상태: <strong>{'진행중' if started else '대기중'}</strong></p></section>
<section class='grid'>
<form class='card' method='post'><h3>시작 인원 변경</h3><input type='hidden' name='action' value='set_threshold'>
<label>임계치 <input type='number' min='1' name='threshold' value='{threshold}'></label><button type='submit'>저장</button></form>
<form class='card' method='post'><h3>즉시 시작</h3><input type='hidden' name='action' value='start_now'><button type='submit'>지금 시작</button></form>
<form class='card' method='post'><h3>세션 리셋</h3><input type='hidden' name='action' value='reset'><button type='submit'>참가자 초기화 + 시작상태 해제</button></form></section>"""
        return response(start_response, "200 OK", html_page("운영자 페이지", body))

    return response(start_response, "404 Not Found", html_page("404", "<section class='card'><h2>페이지를 찾을 수 없습니다.</h2></section>"))


if __name__ == "__main__":
    init_db()
    with make_server("0.0.0.0", 5000, app) as server:
        print("Serving on http://0.0.0.0:5000")
        server.serve_forever()

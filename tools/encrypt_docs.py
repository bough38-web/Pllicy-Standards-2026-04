#!/usr/bin/env python3
"""정책 문서 암호화 게시 도구.

_src/ 의 평문 HTML(로컬 전용, 저장소에 올리지 않음)을 비밀번호로 암호화해서, 같은 경로의
"잠금 페이지"로 저장소 루트에 써낸다. GitHub Pages에는 이 잠금 페이지(암호문)만 올라가므로
주소를 알아도 비밀번호 없이는 내용을 볼 수 없다.

  암호화: AES-256-GCM, 키는 PBKDF2-HMAC-SHA256(600,000회)로 비밀번호에서 유도, 문서마다 무작위 salt/IV
  복호화: 브라우저 WebCrypto (같은 방식) — 서버 없이 페이지 안에서만 풀린다

사용법 (저장소 루트에서):
  python3 -m pip install cryptography
  python3 tools/encrypt_docs.py            # 비밀번호를 물어본다(화면에 안 보임)
  PP_PASSWORD='...' python3 tools/encrypt_docs.py

새 문서를 추가하려면: _src/ 에 평문 HTML을 넣고, _src/index.html 목차에 링크를 추가한 뒤 다시 실행.
비밀번호를 바꾸려면: 새 비밀번호로 다시 실행하면 모든 문서가 새 비밀번호로 다시 암호화된다.
"""
import base64, getpass, html, os, secrets, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "_src"
ITERATIONS = 600_000
MIN_LEN = 10


def encrypt(plaintext: bytes, password: str) -> dict:
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, plaintext, None)  # 인증태그 포함 → 틀린 비밀번호/변조 감지
    b64 = lambda b: base64.b64encode(b).decode()
    return {"salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


def lock_page(title: str, enc: dict) -> str:
    t = html.escape(title)
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{t}</title>
<style>
  body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:#f6f8fb;
    font-family:'Pretendard','Apple SD Gothic Neo','Malgun Gothic',sans-serif;color:#1f2937}}
  .box{{background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:36px 28px;box-shadow:0 10px 28px rgba(0,0,0,.06);max-width:400px;width:100%;text-align:center}}
  h1{{font-size:20px;margin:0 0 6px;color:#0b2f6b}} p{{color:#6b7280;font-size:13px;margin:0 0 18px}}
  input[type=password]{{padding:12px;border:1px solid #c7d2fe;border-radius:8px;width:100%;font-size:16px;box-sizing:border-box;outline:none;font-family:inherit}}
  input[type=password]:focus{{border-color:#0b2f6b}}
  label{{display:block;text-align:left;font-size:12px;color:#6b7280;margin:10px 0 14px;cursor:pointer}}
  button{{padding:12px;background:#0b2f6b;color:#fff;border:none;border-radius:8px;width:100%;font-size:16px;font-weight:700;cursor:pointer;font-family:inherit}}
  button:disabled{{opacity:.6;cursor:wait}}
  #err{{color:#dc2626;font-size:13px;min-height:18px;margin:8px 0 0}}
</style>
</head>
<body>
<div class="box" id="box" style="display:none">
  <h1>🔒 보안 문서</h1>
  <p>{t}<br>열람하려면 비밀번호를 입력하세요.</p>
  <form id="f"><input type="password" id="pw" placeholder="비밀번호" autocomplete="current-password" autofocus>
  <label><input type="checkbox" id="keep"> 이 기기에서 비밀번호 기억</label>
  <button id="btn">열기</button></form>
  <div id="err"></div>
</div>
<script id="enc" type="application/json">{{"v":1,"it":{ITERATIONS},"salt":"{enc['salt']}","iv":"{enc['iv']}","ct":"{enc['ct']}"}}</script>
<script>
(function(){{
  var E=JSON.parse(document.getElementById('enc').textContent);
  function b(s){{var r=atob(s),n=r.length,u=new Uint8Array(n);for(var i=0;i<n;i++)u[i]=r.charCodeAt(i);return u;}}
  function get(k){{try{{return sessionStorage.getItem(k)||localStorage.getItem(k);}}catch(e){{return null;}}}}
  async function open(pw){{
    var km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    var key=await crypto.subtle.deriveKey({{name:'PBKDF2',salt:b(E.salt),iterations:E.it,hash:'SHA-256'}},km,{{name:'AES-GCM',length:256}},false,['decrypt']);
    var pt=await crypto.subtle.decrypt({{name:'AES-GCM',iv:b(E.iv)}},key,b(E.ct));
    return new TextDecoder().decode(pt);
  }}
  function show(h){{document.open();document.write(h);document.close();
    if(location.hash){{var id=location.hash;setTimeout(function(){{var el=document.querySelector(id);if(el)el.scrollIntoView();}},50);}}}}
  var saved=get('pp_pw');
  (saved?open(saved):Promise.reject()).then(show).catch(function(){{
    document.getElementById('box').style.display='';
    var f=document.getElementById('f'),btn=document.getElementById('btn'),err=document.getElementById('err');
    f.onsubmit=function(ev){{ev.preventDefault();var pw=document.getElementById('pw').value;if(!pw)return;
      btn.disabled=true;btn.textContent='확인 중…';err.textContent='';
      open(pw).then(function(h){{
        try{{sessionStorage.setItem('pp_pw',pw);if(document.getElementById('keep').checked)localStorage.setItem('pp_pw',pw);}}catch(e){{}}
        show(h);
      }}).catch(function(){{err.textContent='비밀번호가 일치하지 않습니다.';btn.disabled=false;btn.textContent='열기';}});
    }};
  }});
}})();
</script>
</body>
</html>
"""


def main():
    if not SRC.is_dir():
        sys.exit(f"평문 원본 폴더가 없습니다: {SRC}")
    pw = os.environ.get("PP_PASSWORD") or getpass.getpass("문서 비밀번호: ")
    if len(pw) < MIN_LEN:
        sys.exit(f"비밀번호는 {MIN_LEN}자 이상이어야 합니다(짧은 비밀번호는 암호문을 받아가 무차별 대입으로 풀 수 있음).")
    if "PP_PASSWORD" not in os.environ and getpass.getpass("비밀번호 확인: ") != pw:
        sys.exit("비밀번호가 일치하지 않습니다.")
    n = 0
    for src in sorted(SRC.rglob("*.html")):
        rel = src.relative_to(SRC)
        body = src.read_bytes()
        m = body.decode("utf-8", "ignore")
        title = m.split("<title>", 1)[1].split("</title>", 1)[0].strip() if "<title>" in m else rel.stem
        out = ROOT / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(lock_page(title, encrypt(body, pw)), encoding="utf-8")
        print(f"  🔒 {rel}  ({len(body)//1024:,} KB)")
        n += 1
    print(f"완료: {n}개 문서 암호화")


if __name__ == "__main__":
    main()

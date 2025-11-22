# web_secure.py
from flask import Flask, request, redirect, render_template, url_for, flash
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'secret_key'  # 실습용. 운영 시 안전한 값 사용 권장

# ---- 경로 설정 ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, '../file/upload')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# (요청에 따라) 업로드 용량 제한 제거: MAX_CONTENT_LENGTH 설정 없음

# HTTPS 전제 쿠키 보안 옵션(선택 유지)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# ---- 라우트 ----
@app.route('/')
def upload_form():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('파일을 선택하세요')
        return redirect(url_for('upload_form'))

    file = request.files['file']
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    print(f"File:{getattr(file, 'filename', '')}\nUsername:{username}\nPassword:{password}")

    # pwfile.txt 경로
    pwfile_path = os.path.join(BASE_DIR, 'pwfile.txt')
    if not os.path.exists(pwfile_path):
        flash('서버 계정 파일(pwfile.txt)이 없습니다.')
        return redirect(url_for('upload_form'))

    # 사용자 인증
    approved = False
    with open(pwfile_path, 'r', encoding='utf-8') as pwfile:
        for line in pwfile:
            line = line.strip()
            if not line or ':' not in line:
                continue
            approved_user, approved_password = [x.strip() for x in line.split(':', 1)]
            if username == approved_user and password == approved_password:
                approved = True
                break

    if not approved:
        flash('승인되지 않은 사용자입니다.')
        return redirect(url_for('upload_form'))

    # 파일 저장
    if file.filename == '':
        flash('파일이 존재하지 않습니다.')
        return redirect(url_for('upload_form'))

    filename = secure_filename(file.filename)  # 파일명 안전화
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(save_path)

    flash(f"File '{filename}' 성공적으로 업로드 되었습니다!")
    return redirect(url_for('upload_form'))

# ---- 실행 (mkcert 인증서 사용) ----
if __name__ == '__main__':
    CERT_FILE = os.path.join(BASE_DIR, 'localhost+3.pem')
    KEY_FILE  = os.path.join(BASE_DIR, 'localhost+3-key.pem')

    app.run(host='0.0.0.0', port=5000, debug=True,
            ssl_context=(CERT_FILE, KEY_FILE))

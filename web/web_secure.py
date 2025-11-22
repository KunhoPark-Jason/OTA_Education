from flask import Flask, request, redirect, render_template, url_for, flash
import os

app = Flask(__name__)
app.secret_key = 'secret_key'

# 현재 디렉토리 기준으로 'upload' 폴더 경로 설정
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../file/upload')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # 'upload' 폴더가 없으면 생성

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def upload_form():
    return render_template('upload.html')  # 플래시 메시지는 템플릿에서 처리

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('파일을 선택하세요')  # 플래시 메시지 추가
        return redirect(url_for('upload_form'))
    file = request.files['file']
    username = request.form['username']
    password = request.form['password']

    print(f"File:{file.filename}\nUsername:{username}\nPassword:{password}")

    with open('pwfile.txt', 'r') as pwfile:
        lines = pwfile.readlines()
        for line in lines:
            approved_user = line.split(':')[0].strip()
            approved_password = line.split(':')[1].strip()
            if username == approved_user and password == approved_password:
                print(f"승인된 사용자: {approved_user}")
                if file.filename == '':
                    flash('파일이 존재하지 않습니다.')  # 플래시 메시지 추가
                    return redirect(url_for('upload_form'))
                if file:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                    file.save(file_path)
                    flash(f"File '{file.filename}' 성공적으로 업로드 되었습니다!")  # 플래시 메시지 추가
                    return redirect(url_for('upload_form'))
        flash('승인되지 않은 사용자입니다.')  # 플래시 메시지 추가
        return redirect(url_for('upload_form'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


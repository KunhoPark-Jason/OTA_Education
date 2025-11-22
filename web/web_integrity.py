from flask import Flask, request, redirect, render_template, url_for, flash
import os
import hashlib  # 추가된 모듈

app = Flask(__name__)
app.secret_key = 'secret_key'

# 현재 디렉토리 기준으로 'temp' 폴더 경로 설정
TEMP_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp')
os.makedirs(TEMP_FOLDER, exist_ok=True)  # 'temp' 폴더가 없으면 생성

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'upload')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # 'upload' 폴더가 없으면 생성

HASH_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hash')
os.makedirs(HASH_FOLDER, exist_ok=True)  # 'hash' 폴더가 없으면 생성

app.config['TEMP_FOLDER'] = TEMP_FOLDER

@app.route('/')
def upload_form():
    return render_template('upload_integrity.html')  # 플래시 메시지는 템플릿에서 처리

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file1' not in request.files or 'file2' not in request.files:
        flash('두 개의 파일을 모두 선택하세요')  # 플래시 메시지 추가
        return redirect(url_for('upload_form'))
    
    file1 = request.files['file1']
    file2 = request.files['file2']
    username = request.form['username']
    password = request.form['password']

    print(f"File1: {file1.filename}, File2: {file2.filename}\nUsername: {username}\nPassword: {password}")

    with open('pwfile.txt', 'r') as pwfile:
        lines = pwfile.readlines()
        for line in lines:
            approved_user = line.split(':')[0].strip()
            approved_password = line.split(':')[1].strip()
            if username == approved_user and password == approved_password:
                print(f"승인된 사용자: {approved_user}")
                if file1.filename == '' or file2.filename == '':
                    flash('두 파일 중 하나가 존재하지 않습니다.')  # 플래시 메시지 추가
                    return redirect(url_for('upload_form'))
                if file1 and file2:
                    # Save files temporarily
                    file1_path = os.path.join(app.config['TEMP_FOLDER'], file1.filename)
                    file2_path = os.path.join(app.config['TEMP_FOLDER'], file2.filename)
                    file1.save(file1_path)
                    file2.save(file2_path)

                    try:
                        # Compute hash of file1
                        with open(file1_path, 'rb') as f1:
                            file1_hash = hashlib.sha256(f1.read()).hexdigest()

                        # Read hash from file2
                        with open(file2_path, 'r', encoding='utf-8') as f2:
                            file2_hash = f2.read().strip()

                        # Compare hashes
                        if file1_hash != file2_hash:
                            flash('파일의 해시가 일치하지 않습니다. 잘못된 파일입니다.')  # 플래시 메시지 추가
                            return redirect(url_for('upload_form'))

                        # Delete existing file in upload folder if it exists
                        upload_path = os.path.join(UPLOAD_FOLDER, file1.filename)
                        if os.path.exists(upload_path):
                            os.remove(upload_path)

                        # Move file1 to upload folder if hashes match
                        os.rename(file1_path, upload_path)

                        # Save the hash to the hash directory
                        hash_path = os.path.join(HASH_FOLDER, f"{file1.filename}.hash")
                        with open(hash_path, 'w', encoding='utf-8') as hash_file:
                            hash_file.write(file1_hash)
                        print(f"Hash saved to {hash_path}")

                        flash(f"Files '{file1.filename}' and '{file2.filename}' 성공적으로 업로드 및 검증되었습니다!")  # 플래시 메시지 추가
                        return redirect(url_for('upload_form'))
                    finally:
                        # Clean up temporary files
                        if os.path.exists(file1_path):
                            os.remove(file1_path)
                        if os.path.exists(file2_path):
                            os.remove(file2_path)
        flash('승인되지 않은 사용자입니다.')  # 플래시 메시지 추가
        return redirect(url_for('upload_form'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


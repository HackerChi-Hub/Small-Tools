from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# 创建数据库和测试数据
def init_db():
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'test', 'test123')")
    conn.commit()
    conn.close()

# 易受攻击的查询模板
TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>测试网站</title>
    <style>
        body { padding: 20px; font-family: Arial; }
        .result { margin-top: 20px; }
    </style>
</head>
<body>
    <h2>用户搜索</h2>
    <form method="GET">
        <input type="text" name="username" placeholder="输入用户名">
        <input type="submit" value="搜索">
    </form>
    <div class="result">
        {% if error %}
            <p style="color: red;">{{ error }}</p>
        {% endif %}
        {% if result %}
            <p>查询结果: {{ result }}</p>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    username = request.args.get('username', '')
    if username:
        try:
            conn = sqlite3.connect('test.db')
            c = conn.cursor()
            # 故意使用不安全的查询方式
            query = f"SELECT * FROM users WHERE username = '{username}'"
            c.execute(query)
            result = c.fetchall()
            conn.close()
            return render_template_string(TEMPLATE, result=result)
        except Exception as e:
            return render_template_string(TEMPLATE, error=str(e))
    return render_template_string(TEMPLATE)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
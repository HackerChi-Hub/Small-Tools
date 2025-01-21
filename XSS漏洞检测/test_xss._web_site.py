from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# 存储型 XSS 漏洞的简单存储
stored_comments = []

# 首页
@app.route('/')
def index():
    return """
    <h1>漏洞演示网站</h1>
    <ul>
        <li><a href="/reflect?query=test">反射型 XSS 漏洞</a></li>
        <li><a href="/store">存储型 XSS 漏洞</a></li>
        <li><a href="/dynamic">动态加载 XSS 漏洞</a></li>
        <li><a href="/csp">CSP 测试页面</a></li>
        <li><a href="/nocsp">无 CSP 测试页面</a></li>
    </ul>
    """

# 反射型 XSS 漏洞
@app.route('/reflect')
def reflect():
    query = request.args.get('query', '')
    return f"""
    <h1>反射型 XSS 漏洞</h1>
    <p>输入内容将直接反射到页面上：</p>
    <p>{query}</p>
    <a href="/">返回首页</a>
    """

# 存储型 XSS 漏洞
@app.route('/store', methods=['GET', 'POST'])
def store():
    global stored_comments
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        stored_comments.append(comment)
        return redirect(url_for('store'))
    
    comments_html = "<br>".join(stored_comments)
    return f"""
    <h1>存储型 XSS 漏洞</h1>
    <form method="post">
        <label for="comment">评论:</label>
        <input type="text" id="comment" name="comment">
        <button type="submit">提交</button>
    </form>
    <h2>评论列表:</h2>
    <div>{comments_html}</div>
    <a href="/">返回首页</a>
    """

# 动态加载 XSS 漏洞
@app.route('/dynamic')
def dynamic():
    return """
    <h1>动态加载 XSS 漏洞</h1>
    <p>点击按钮动态加载内容：</p>
    <button id="load-content">加载内容</button>
    <div id="dynamic-area"></div>
    <script>
        document.getElementById('load-content').onclick = function() {
            var dynamicArea = document.getElementById('dynamic-area');
            dynamicArea.innerHTML = prompt("请输入内容：");
        };
    </script>
    <a href="/">返回首页</a>
    """

# 含 CSP 的页面
@app.route('/csp')
def csp():
    response = app.response_class(
        response="""
        <h1>含 CSP 的页面</h1>
        <p>此页面启用了 CSP 策略，禁止外部脚本加载。</p>
        <script>alert('CSP 测试');</script>
        <a href="/">返回首页</a>
        """,
        status=200,
        mimetype='text/html'
    )
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response

# 不含 CSP 的页面
@app.route('/nocsp')
def nocsp():
    return """
    <h1>无 CSP 的页面</h1>
    <p>此页面未启用 CSP 策略，易受攻击。</p>
    <script>alert('无 CSP 测试');</script>
    <a href="/">返回首页</a>
    """

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
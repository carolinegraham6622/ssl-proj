from flask import Flask, render_template
import pymysql

conn = pymysql.connect(database='ssl_check', host='db', user='root', password='1234')

app = Flask(__name__)

@app.route("/")
def main():
    #return render_template('./indextest.html')
    cur = conn.cursor()
    cur.execute("select * from cert")
    results = cur.fetchall()
    #conn.close()
    return render_template('./index.html', results=results)
if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0')
from flask import Flask, render_template
import pymysql

conn = pymysql.connect(database='ssl_check', host='db', user='root', password='1234')

app = Flask(__name__)

@app.route("/")
def home():
    cur = conn.cursor()
    #pull from the last 30 days
    cur.execute("select * from cert where start_time > NOW() - INTERVAL 30 DAY;")
    results = cur.fetchall()
    #conn.close()
    return render_template('./home.html', results=results)

@app.route("/lastYear/")
def lastYear():
    cur = conn.cursor()
    cur.execute("select * from cert where start_time > NOW() - INTERVAL 365 DAY;")
    results = cur.fetchall()
    #conn.close()
    return render_template('./home.html', results=results)

@app.route("/showAll/")
def showAll():
    cur = conn.cursor()
    #pull all rows
    cur.execute("select * from cert")
    results = cur.fetchall()
    #conn.close()
    return render_template('./home.html', results=results)


if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0')
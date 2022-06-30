from flask import Flask, render_template
import pymysql

conn = pymysql.connect(database='ssl_check', host='db', user='root', password='1234')

app = Flask(__name__)

@app.route("/")
def home():
    cur = conn.cursor()
    #pull from the last 30 days
    cur.execute("select host_ip, host_name, port_num, issuer_name, creation_date, expiration_date, expires_in from certmodel where start_time > NOW() - INTERVAL 30 DAY and expires_in > -30 order by expiration_date DESC")
    results = cur.fetchall()
    return render_template('./home.html', results=results)

@app.route("/lastYear")
def homelastyear():
    cur = conn.cursor()
    #pull from the last year
    cur.execute("select host_ip, host_name, port_num, issuer_name, creation_date, expiration_date, expires_in from certmodel where start_time > NOW() - INTERVAL 365 DAY and expires_in > -365 order by expiration_date ASC")
    results = cur.fetchall()
    return render_template('./home_lastyear.html', results=results)

@app.route("/showAll")
def homeshowall():
    cur = conn.cursor()
    #pull from all
    cur.execute("select host_ip, host_name, port_num, issuer_name, creation_date, expiration_date, expires_in from certmodel order by expiration_date DESC")
    results = cur.fetchall()
    return render_template('./home_showall.html', results=results)

if __name__ == '__main__':
  # refactoring (fix?)
  app.run(debug=True, host='0.0.0.0') 
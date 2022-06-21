FROM python:3

WORKDIR /usr/src/app

COPY . .
RUN apt-get update && apt-get install -y nmap sqlite3
RUN pip install --no-cache-dir -r requirements.txt
CMD [ "python", "./nmap-example.py" ]
# CMD [ "python", "./logexample.py" ]
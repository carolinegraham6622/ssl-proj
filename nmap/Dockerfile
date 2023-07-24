FROM python:3

WORKDIR /usr/src/app

COPY . .
RUN apt-get update && apt-get install -y nmap sqlite3
RUN pip install --no-cache-dir -r requirements.txt
# CMD ["nmap","-sV","-sC","-oX","/tmp/nmap_output.xml","150.250.77.250"]
CMD [ "python", "./main.py" ]
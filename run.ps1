docker-compose stop nmap
docker-compose rm -f nmap
docker-compose build
docker-compose up -d nmap
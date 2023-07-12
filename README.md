# auth
docker build -t auth-service .
docker run --env-file ./.env  -p 8282:8080 -d --restart unless-stopped auth-service
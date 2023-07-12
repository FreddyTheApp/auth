# auth
docker build -t auth-service .
docker run --env-file ./.env  -p 8080:8080 auth-service
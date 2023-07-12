.PHONY: docker-build

APPNAME := auth

docker-build:
	docker build --platform linux/amd64 -t auth-service .


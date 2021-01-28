docker-build:
	docker build -t keycloak-proxy:v0.1.0 ./

google-docker-build:
	docker build -t gcr.io/carpolice/keycloak-proxy:v0.1.0 ./

google-docker-push:
	docker push gcr.io/carpolice/keycloak-proxy:v0.1.0

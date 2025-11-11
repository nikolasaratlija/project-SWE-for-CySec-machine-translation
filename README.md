Repository for the Tilburg University "SWE for CySec" course group project, Group 1

docker-compose build
docker-compose run --rm translation-service flask init-db
docker-compose run --rm auth-service flask init-db
docker-compose up
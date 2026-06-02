.PHONY: run build stop logs clean setup

run:
	docker compose up -d

build:
	docker compose up --build -d

stop:
	docker compose down

logs:
	docker compose logs -f

clean:
	docker compose down -v
	rm -f proxy/proxy

setup:
	./setup.sh

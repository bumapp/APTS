FROM php:8.2-cli
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping libsqlite3-dev \
 && docker-php-ext-install pdo_sqlite \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY index.php .
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "index.php"]

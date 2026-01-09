FROM nginx:alpine

COPY index.html /usr/share/nginx/html/index.html
COPY flag.txt /flag.txt

# Set proper permissions
RUN chmod 444 /flag.txt

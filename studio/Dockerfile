FROM nginxinc/nginx-unprivileged:1.31-alpine

# Operating-system packages fixed since the base image was built (the release workflow scans the result and refuses fixable high or critical findings).
USER root
RUN apk upgrade --no-cache
# The studio does not run as root: this image's nginx runs as an unprivileged user and listens on 8080 (a port above 1024), so it needs no extra privileges at all.
USER 101
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
EXPOSE 8080

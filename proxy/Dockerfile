FROM nginx:1.27

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

COPY ./nginx.conf.template /opt/nginx/nginx.conf.template
COPY ./nginx-template-subst.sh /bin/nginx-template-subst.sh
RUN chmod +x /bin/nginx-template-subst.sh

CMD ["/bin/bash", "-c", "/bin/nginx-template-subst.sh && exec nginx -g 'daemon off;'"]

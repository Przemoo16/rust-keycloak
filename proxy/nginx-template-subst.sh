#!/bin/bash

DNS_SERVER=$( \
    grep -i '^nameserver' /etc/resolv.conf | head -n1 | cut -d ' ' -f2 \
)
export DNS_SERVER
export APP_UPSTREAM="${APP_UPSTREAM:-"http://app"}"
export AUTH_UPSTREAM="${AUTH_UPSTREAM:-"http://auth"}"

envsubst '$DNS_SERVER $APP_UPSTREAM $AUTH_UPSTREAM' \
    < /opt/nginx/nginx.conf.template > /etc/nginx/conf.d/default.conf

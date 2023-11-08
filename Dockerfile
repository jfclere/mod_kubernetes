FROM quay.io/fedora/httpd-24
COPY mod_kubernetes.so /usr/lib64/httpd/modules/
COPY mod_kubernetes.conf /etc/httpd/conf.d/mod_kubernetes.conf

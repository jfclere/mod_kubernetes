FROM quay.io/fedora/httpd-24
COPY mod_kubernetes.so /usr/lib64/httpd/modules/
COPY mod_kubernetes.conf /etc/httpd/conf.modules.d/99-mod_kubernetes.conf

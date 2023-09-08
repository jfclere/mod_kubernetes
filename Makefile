mod_kubernetes: mod_kubernetes.c
	cc -c -I${HOME}/APR-1.7.x/include/apr-1 mod_kubernetes.c
	cc -o mod_kubernetes mod_kubernetes.o ${HOME}/APR-1.7.x/lib/libapr-1.a
image: mod_kubernetes Dockerfile
	podman build --tag quay.io/jfclere/fedora -f ./Dockerfile
	podman push quay.io/jfclere/fedora
run: image
	podman run -it --name myhttpd --rm quay.io/jfclere/fedora:myhttpd mod_kubernetes google.com

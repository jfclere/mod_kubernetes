# mod_kubernetes
playing with mod_balancer and kubernetes

# The httpd from fedora listen on 8080/8443
/etc/httpd/conf/httpd.conf

/etc/httpd/conf.d/ssl.conf

To expose it;
```bash
oc expose pod/test-pod --port 8080
oc expose svc test-pod
```

Testing:
```bash
kubectl scale deployment/tomcat --replicas=2
```
Then:
```
[jfclere@dhcp-144-142 mod_kubernetes]$ kubectl get pods
NAME                      READY   STATUS    RESTARTS   AGE
test-pod                  1/1     Running   0          6m20s
tomcat-577955dbfc-4vj9z   1/1     Running   0          2m3s
tomcat-577955dbfc-98k6t   1/1     Running   0          22h
```
Delete one of the tomcat pod
```
[jfclere@dhcp-144-142 mod_kubernetes]$ kubectl delete pod/tomcat-577955dbfc-98k6t
pod "tomcat-577955dbfc-98k6t" deleted
```

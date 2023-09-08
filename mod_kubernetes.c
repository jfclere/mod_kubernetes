#include "apr.h"
#include "apr_pools.h"
#include "apr_general.h"
#include "apr_file_io.h"
#include "apr_errno.h"
#include "apr_inherit.h"
#include "apr_network_io.h"

static void kubernetes_watchdog_func(const char *servicename, apr_pool_t *pool)
{
    apr_status_t rv;
    apr_sockaddr_t *sa;
    apr_pool_t *ptemp;
    apr_pool_create(&ptemp, pool);
    rv = apr_sockaddr_info_get(&sa, servicename, APR_UNSPEC, 8080, 0, ptemp);
    if (rv == APR_SUCCESS) {
        while(sa) {
            char *ip_addr;
            apr_sockaddr_ip_get(&ip_addr, sa);
            printf("JFC find address %s %s %s\n", ip_addr, sa->hostname,  sa->servname);
            sa = sa->next;
        }
    } else
        printf("No pod for the service: %s\n", servicename);
    fflush(stdout);
    apr_pool_destroy(ptemp);

}

int main(int argc, const char * const *argv)
{
    apr_pool_t *ptemp;
    const char *servicename;

    if (argc == 2)
        servicename = argv[1];
    else
        servicename = "localhost";
    printf("Using service: %s\n", servicename);

    apr_initialize();
    apr_pool_create(&ptemp, NULL);
    for(;;) {
        kubernetes_watchdog_func(servicename, ptemp);
        apr_sleep(apr_time_from_sec(10));
    }
    apr_terminate();
}

/*
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_proxy.h"
#include "mod_watchdog.h"

#define K8S_WATHCHDOG_NAME ("_k8s_cluster_")

struct proxy_node_table {
   char *host;
   int alreadyin;
   struct proxy_node_table *next;
};

struct proxy_worker_table {
   proxy_worker *worker;
   struct proxy_worker_table *next;
};

static ap_watchdog_t *watchdog;
static apr_time_t last = 0;
static apr_time_t interval = apr_time_from_sec(HCHECK_WATHCHDOG_DEFAULT_INTERVAL);

static APR_OPTIONAL_FN_TYPE(balancer_manage) *balancer_manage = NULL;

static struct proxy_node_table *kubernetes_watchdog_func(const char *servicename, apr_pool_t *pool, server_rec *s)
{
    apr_status_t rv;
    apr_sockaddr_t *sa;
    apr_pool_t *ptemp;
    struct proxy_node_table *table = NULL;
    apr_pool_create(&ptemp, pool);
    rv = apr_sockaddr_info_get(&sa, servicename, APR_UNSPEC, 8080, 0, ptemp);
    if (rv == APR_SUCCESS) {
        while(sa) {
            char *ip_addr;
            struct proxy_node_table *ctable = table;
            apr_sockaddr_ip_get(&ip_addr, sa);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "kubernetes_watchdog_func: find address %s %s %s",
                         ip_addr, sa->hostname,  sa->servname);
            if (ctable) {
                ctable->next = apr_pcalloc(pool, sizeof(struct proxy_node_table));
                ctable = ctable->next;
            } else
                ctable = apr_pcalloc(pool, sizeof(struct proxy_node_table));
            ctable->host = apr_pstrdup(pool, ip_addr);
            
            sa = sa->next;
        }
    } else
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "kubernetes_watchdog_func:  No pod for the service: %s", servicename);
    apr_pool_destroy(ptemp);
    return table;
}


/**
 * Builds the parameters for mod_balancer
 */
#define Type "http"
#define Port 8080
static apr_status_t mod_manager_manage_worker(request_rec *r, const char *balancer, const char *hostname)
{
    apr_table_t *params;
    params = apr_table_make(r->pool, 10);
    /* balancer */
    apr_table_set(params, "b", balancer);

    /* and new worker */
    apr_table_set(params, "b_wyes", "1");
    apr_table_set(params, "b_nwrkr",
                  apr_pstrcat(r->pool, Type, "://", hostname, ":", Port, NULL));
    balancer_manage(r, params);
    apr_table_clear(params);

    /* now process the worker */
    apr_table_set(params, "b", balancer);
    apr_table_set(params, "w",
                  apr_pstrcat(r->pool, Type, "://", hostname, ":", Port, NULL));
    apr_table_set(params, "w_wr", hostname); /* XXX: we need something here! */
    apr_table_set(params, "w_status_D", "0"); /* Not Dissabled */

    /* set the health check (requires mod_proxy_hcheck) */
    /* CPING for AJP and OPTIONS for HTTP/1.1 */
    if (strcmp(Type, "ajp")) {
        apr_table_set(params, "w_hm", "OPTIONS");
    } else {
        apr_table_set(params, "w_hm", "CPING");
    }
    /* Use 10 sec for the moment, the idea is to adjust it with the STATUS frequency */
    apr_table_set(params, "w_hi", "10000");
    return balancer_manage(r, params);
}

static void remove_removed_node(server_rec *s, apr_pool_t *pool, apr_time_t now, struct proxy_worker_table *worker_table)
{
    /* Calls mod_manager_manage_worker */
}

static void addworkersfromtable(struct proxy_node_table *node_table)
{
    /* Calls mod_manager_manage_worker */
}

/* check if the worker is in the pod list otherwise add it to the toremove list */
static int isworkerintable(apr_pool_t *pool, proxy_worker *worker, struct proxy_node_table *node_table, struct proxy_worker_table *worker_table) {
    struct proxy_node_table *ctable = node_table;
    struct proxy_worker_table *cworkertable = worker_table;
    int intable = 0;
    while (ctable) {
        if (!strcpy(ctable->host, worker->s->hostname)) {
             ctable->alreadyin = 1;
             return 1;
        }
        ctable = ctable->next;
    }
    /* here the worker is NOT in the node table */
    if (!cworkertable) {
       cworkertable = apr_pcalloc(pool, sizeof(struct proxy_worker_table));
       worker_table = cworkertable;
       cworkertable->worker = worker; 
    } else {
       while (cworkertable->next)
            cworkertable = cworkertable->next;
       cworkertable->next = apr_pcalloc(pool, sizeof(struct proxy_worker_table));
       cworkertable = cworkertable->next; 
       cworkertable->worker = worker;
    }
    return 0;
}

static apr_status_t k8s_watchdog_callback(int state, void *data, apr_pool_t *pool)
{
    apr_status_t rv = APR_SUCCESS;
    server_rec *s = (server_rec *)data;
    struct proxy_node_table *node_table;
    apr_time_t now;
    switch (state) {
    case AP_WATCHDOG_STATE_STARTING:
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "k8s_watchdog_callback STARTING");
        break;

    case AP_WATCHDOG_STATE_RUNNING:
        /* loop thru all workers */
        struct proxy_worker_table *worker_table = NULL;
        int i;
        void *sconf = s->module_config;
        proxy_server_conf *conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
        proxy_balancer *balancer = (proxy_balancer *)conf->balancers->elts;
        now = apr_time_now();
        if (now - last < interval)
            return rv;
        last = now;
        node_table = kubernetes_watchdog_func("tomcat", pool, s);

        for (i = 0; i < conf->balancers->nelts; i++, balancer++) {
            int n;
            proxy_worker **workers;
            proxy_worker *worker;
            /* Have any new balancers or workers been added dynamically? */
            ap_proxy_sync_balancer(balancer, s, conf);
            workers = (proxy_worker **)balancer->workers->elts;
            for (n = 0; n < balancer->workers->nelts; n++) {
                worker = *workers;
                if (!isworkerintable(pool, worker, node_table, worker_table)) {
                    /* We have to remove it or marke as REMOVED */
                }
                workers++;
            }
            /* add the new pods */
            addworkersfromtable(node_table);
        }

        /* cleanup removed node in shared memory */
        remove_removed_node(s, pool, now, worker_table);
        break;

    case AP_WATCHDOG_STATE_STOPPING:
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "k8s_watchdog_callback STOPPING");
        break;
    }
    return rv;
}

static int proxy_kubernetes_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    APR_OPTIONAL_FN_TYPE(ap_watchdog_get_instance) *k8s_watchdog_get_instance;
    APR_OPTIONAL_FN_TYPE(ap_watchdog_register_callback) *k8s_watchdog_register_callback;
    (void)plog;
    (void)ptemp;

    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    /* get the balancer_manage from mod_proxy_balancer */
    balancer_manage = APR_RETRIEVE_OPTIONAL_FN(balancer_manage);
    if (!balancer_manage) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                     APLOGNO(03262) "proxy_kubernetes_post_config: mod_proxy_balancer is required");
        return !OK;
    }
    /* add our watchdog callback */
    k8s_watchdog_get_instance = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_get_instance);
    k8s_watchdog_register_callback = APR_RETRIEVE_OPTIONAL_FN(ap_watchdog_register_callback);
    if (!k8s_watchdog_get_instance || !k8s_watchdog_register_callback) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                     APLOGNO(03262) "proxy_kubernetes_post_config: mod_watchdog is required");
        return !OK;
    }
    if (k8s_watchdog_get_instance(&watchdog, K8S_WATHCHDOG_NAME, 0, 1, p)) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                     APLOGNO(03263) "proxy_kubernetes_post_config: Failed to create watchdog instance (%s)",
                     K8S_WATHCHDOG_NAME);
        return !OK;
    }
    while (s) {
        if (k8s_watchdog_register_callback(watchdog, AP_WD_TM_SLICE, s, k8s_watchdog_callback)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                         APLOGNO(03264) "proxy_kubernetescluster_post_config: Failed to register watchdog callback (%s)",
                         K8S_WATHCHDOG_NAME);
            return !OK;
        }
        s = s->next;
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(proxy_kubernetes_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(proxy_kubernetes) = {
    STANDARD20_MODULE_STUFF,
    NULL,               /* create per-directory config structure */
    NULL,               /* merge per-directory config structures */
    NULL,               /* create per-server config structure */
    NULL,               /* merge per-server config structures */
    NULL,               /* command apr_table_t */
    register_hooks,     /* register hooks */
    AP_MODULE_FLAG_NONE /* flags */
};


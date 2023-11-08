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
            } else {
                ctable = apr_pcalloc(pool, sizeof(struct proxy_node_table));
                table = ctable;
            }
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
#define Port "8080"
static apr_status_t mod_manager_manage_worker(request_rec *r, const char *hostname, const char *balancer)
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


/* (copied from mod_proxy_hcheck.c)
 * Create a dummy request rec, simply so we can use ap_expr.
 * Use our short-lived pool for bucket_alloc so that we can simply move
 * buckets and use them after the backend connection is released.
 */
static request_rec *create_request_rec(apr_pool_t *p, server_rec *s,
                                       proxy_balancer *balancer,
                                       const char *method,
                                       const char *protocol)
{
    request_rec *r;

    r = apr_pcalloc(p, sizeof(request_rec));
    r->pool            = p;
    r->server          = s;

    r->per_dir_config = r->server->lookup_defaults;
    if (balancer->section_config) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool,
                                                     r->per_dir_config,
                                                     balancer->section_config);
    }

    r->proxyreq        = PROXYREQ_RESPONSE;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 1);
    r->trailers_in     = apr_table_make(r->pool, 1);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->trailers_out    = apr_table_make(r->pool, 1);
    r->notes           = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    /* Must be set before we run create request hook */

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_OK;  /* Until further notice */
    r->the_request     = NULL;

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;


    /* Time to populate r with the data we have. */
    r->method = method;
    /* Provide quick information about the request method as soon as known */
    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_OPTIONS
            || (r->method_number == M_GET && r->method[0] == 'H')) {
        r->header_only = 1;
    }
    else {
        r->header_only = 0;
    }
    r->protocol = "HTTP/1.0";
    r->proto_num = HTTP_VERSION(1, 0);
    if ( protocol && (protocol[7] == '1') ) {
        r->protocol = "HTTP/1.1";
        r->proto_num = HTTP_VERSION(1, 1);
    }
    r->hostname = NULL;
    r->connection = apr_pcalloc(p, sizeof(conn_rec));
    r->connection->log_id = "-";
    r->connection->conn_config = ap_create_conn_config(p);

    return r;
}

static void addworkersfromtable(struct proxy_node_table *node_table, apr_pool_t *p, server_rec *s, proxy_balancer *balancer)
{
    /* Calls mod_manager_manage_worker */
    struct proxy_node_table *ctable = node_table;
    while (ctable) {
        if (!ctable->alreadyin) {
            request_rec *r;
            r = create_request_rec(p, s, balancer, "GET", "http" );
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "addworkersfromtable: %s add to %s", ctable->host, &balancer->s->name[11]);
            mod_manager_manage_worker(r, ctable->host, &balancer->s->name[11]);
        }
        ctable = ctable->next;
    }
}
static void remove_worker(apr_pool_t *p, server_rec *s, proxy_balancer *balancer, const char *workername)
{
    request_rec *r;
    apr_table_t *params;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "remove_worker: removing %s from %s", workername, &balancer->s->name[11]);
    r = create_request_rec(p, s, balancer, "GET", "http" );
    params = apr_table_make(r->pool, 10);
    apr_table_set(params, "b", &balancer->s->name[11]);
    apr_table_set(params, "w", workername);
    apr_table_set(params, "w_status_D", "1"); /* Dissabled */
    apr_table_set(params, "w_status_S", "1"); /* Stopped */

    balancer_manage(r, params);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "remove_worker: %s removed", workername);
}

/* check if the worker is in the pod list otherwise add it to the toremove list */
static int isworkerintable(apr_pool_t *pool, proxy_worker *worker, struct proxy_node_table *node_table) 
{
    struct proxy_node_table *ctable = node_table;
    int intable = 0;
    while (ctable) {
        if (!strcmp(ctable->host, worker->s->hostname)) {
             ctable->alreadyin = 1;
             return 1;
        }
        ctable = ctable->next;
    }
    /* here the worker is NOT in the node table */
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
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "k8s_watchdog_callback STARTING");
        break;

    case AP_WATCHDOG_STATE_RUNNING:
        /* loop thru all workers */
        int i;
        void *sconf = s->module_config;
        proxy_server_conf *conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
        proxy_balancer *balancer = (proxy_balancer *)conf->balancers->elts;
        now = apr_time_now();
        if (now - last < interval)
            return rv;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "k8s_watchdog_callback RUNNING");
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
                if (!isworkerintable(pool, worker, node_table)) {
                    /* We have to mark it as STOPPPED */
                    if (!PROXY_WORKER_IS(worker, PROXY_WORKER_STOPPED))
                        remove_worker(pool, s, balancer, worker->s->name);
                }
                workers++;
            }
            /* add the new pods */
            addworkersfromtable(node_table, pool, s, balancer);
        }

        break;

    case AP_WATCHDOG_STATE_STOPPING:
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "k8s_watchdog_callback STOPPING");
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


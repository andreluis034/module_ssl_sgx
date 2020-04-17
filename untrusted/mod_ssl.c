#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_connection.h>
//#include "ssl_private.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "mod_ssl.h"
#include "Enclave_u.h"


#include "ssl_private.h"
#include "mod_ssl.h"
#include "mod_ssl_openssl.h"
#include "util_md5.h"
#include "util_mutex.h"
#include "ap_provider.h"
#include "http_config.h"

#include "mod_proxy.h" /* for proxy_hook_section_post_config() */


APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ssl, SSL, int, pre_handshake,
                                    (conn_rec *c,SSL *ssl,int is_proxy),
                                    (c,ssl,is_proxy), OK, DECLINED);

#define SSL_CMD_ALL(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF|OR_AUTHCFG, desc),

#define SSL_CMD_SRV(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF, desc),

#define SSL_CMD_PXY(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF|PROXY_CONF, desc),

#define SSL_CMD_DIR(name, type, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, OR_##type, desc),

#define AP_END_CMD { NULL }



/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave("/opt/httpd/modules/"ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


void InitEnclave()
{
    if(initialize_enclave() < 0){
        return; 
    }
	initSgxLib(global_eid);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

}



static int hello_handler(request_rec* r)
{

    if (!r->handler || strcmp(r->handler, "example-handler")) return (DECLINED);
    const char* hostname;
    r->content_type = "text/html";
    hostname = ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, NULL);
    ap_rputs("<HTML>\n",    r);
    ap_rputs("<HEAD>\n",    r);
    ap_rputs("<TITLE>Hello There</TITLE>\n",    r);
    ap_rputs("</HEAD>\n",    r);
    ap_rputs("<BODY>\n",    r);
    ap_rprintf(r, "Hello %s\n", hostname);
    ap_rputs("</BODY>\n",    r);
    ap_rputs("</HTML>\n",    r);

    return OK;
}

static SSLConnRec *ssl_init_connection_ctx(conn_rec *c,
                                           ap_conf_vector_t *per_dir_config,
                                           int new_proxy)
{
    SSLConnRec *sslconn = myConnConfig(c);
    int need_setup = 0;

    /* mod_proxy's (r->)per_dir_config has the lifetime of the request, thus
     * it uses ssl_engine_set() to reset sslconn->dc when reusing SSL backend
     * connections, so we must fall through here. But in the case where we are
     * called from ssl_init_ssl_connection() with no per_dir_config (which also
     * includes mod_proxy's later run_pre_connection call), sslconn->dc should
     * be preserved if it's already set.
     */
    if (!sslconn) {
        sslconn = apr_pcalloc(c->pool, sizeof(*sslconn));
        need_setup = 1;
    }
    else if (!new_proxy) {
        return sslconn;
    }

    /* Reinit dc in any case because it may be r->per_dir_config scoped
     * and thus a caller like mod_proxy needs to update it per request.
     */
    if (per_dir_config) {
        sslconn->dc = ap_get_module_config(per_dir_config, &ssl_module);
    }
    else {
        sslconn->dc = ap_get_module_config(c->base_server->lookup_defaults,
                                           &ssl_module);
    }

    if (need_setup) {
        sslconn->server = c->base_server;
        sslconn->verify_depth = UNSET;
        if (new_proxy) {
            sslconn->is_proxy = 1;
            sslconn->cipher_suite = sslconn->dc->proxy->auth.cipher_suite;
        }
        else {
            SSLSrvConfigRec *sc = mySrvConfig(c->base_server);
            sslconn->cipher_suite = sc->server->auth.cipher_suite;
        }

        myConnConfigSet(c, sslconn);
    }

    return sslconn;
}
                                 

int ssl_init_ssl_connection(conn_rec *c, request_rec *r)
{
    SSLSrvConfigRec *sc;
    SSL ssl;
    SSLConnRec *sslconn;
    char *vhost_md5;
    int rc;
    modssl_ctx_t *mctx;
    server_rec *server;

    /*
     * Create or retrieve SSL context
     */
    sslconn = ssl_init_connection_ctx(c, r ? r->per_dir_config : NULL, 0);
    server = sslconn->server;
    sc = mySrvConfig(server);

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     */
    ssl_rand_seed(server, c->pool, SSL_RSCTX_CONNECT,
                  sslconn->is_proxy ? "Proxy: " : "Server: ");

    mctx = myCtxConfig(sslconn, sc);

    /*
     * Create a new SSL connection with the configured server SSL context and
     * attach this to the socket. Additionally we register this attachment
     * so we can detach later.
     */
	sgx_status_t  sgxResult = sgx_SSL_new(global_eid, &ssl, mctx->ssl_ctx);
    if (sgxResult != SGX_SUCCESS || !(sslconn->ssl = ssl)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(01962)
                      "Unable to create a new SSL connection from the SSL "
                      "context");
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }

	//TODO Check this cast?
    rc = ssl_run_pre_handshake(c, (SSL*) ssl, sslconn->is_proxy ? 1 : 0);
    if (rc != OK && rc != DECLINED) {
        return rc;
    }

    vhost_md5 = ap_md5_binary(c->pool, (unsigned char *)sc->vhost_id,
                              sc->vhost_id_len);

	int retResult;
	sgxResult = sgx_SSL_set_session_id_context(global_eid, &retResult, ssl, (unsigned char *)vhost_md5, APR_MD5_DIGESTSIZE*2);
    if (!sgxResult)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(01963)
                      "Unable to set session id context to '%s'", vhost_md5);
        ssl_log_ssl_error(SSLLOG_MARK, APLOG_ERR, server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }
	sgx_SSL_set_app_data(global_eid, ssl, c);
    //SSL_set_app_data(ssl, c);
    modssl_set_app_data2(ssl, NULL); /* will be request_rec */

    sgx_SSL_set_verify_result(global_eid, ssl, _X509_V_OK);

    ssl_io_filter_init(c, r, ssl);

    return APR_SUCCESS;

}
static int ssl_hook_pre_connection(conn_rec *c, void *csd)
{
    return ssl_init_ssl_connection(c, NULL);
}

static void ssl_register_hooks(apr_pool_t *pool)
{
	InitEnclave();


    ap_hook_pre_connection(ssl_hook_pre_connection,NULL,NULL, APR_HOOK_MIDDLE);


    /* Create a hook in the request handler, so we get called when a request arrives */
    ap_hook_handler(hello_handler, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA   ssl_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ssl_register_hooks,  /* Our hook registering function */
};
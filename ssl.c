#include "ssl.h"
#include "logging.h"

#include <openssl/rand.h>

static int ssl_initialized = 0;

int
init_ssl(void)
{
    if (ssl_initialized)
        return 0;
    ssl_initialized = 1;

    /* Initialize the OpenSSL library */
    SSL_load_error_strings();
    SSL_library_init();

    /* Make sure we have entropy, or else there's no point to crypto. */
    if (!RAND_poll())
        return 1;

    return 0;
}

SSL_CTX *
new_ssl_ctx(char *cert, char *pkey)
{
    SSL_CTX  *server_ctx;

    if (init_ssl())
        return NULL;

    server_ctx = SSL_CTX_new(SSLv23_method());

    if (!SSL_CTX_use_certificate_chain_file(server_ctx, cert)) {
        skeeter_log(LOG_CRIT, "Could not read server certificate file\n");
        return NULL;
    }
    if (!SSL_CTX_use_PrivateKey_file(server_ctx, pkey, SSL_FILETYPE_PEM)) {
        skeeter_log(LOG_CRIT, "Could not read server private key\n");
        return NULL;
    }

    /* SSLv2 is known to be broken */
    SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);

    return server_ctx;
}

#ifndef _SKEETER_SSL_H
#define _SKEETER_SSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>

int init_ssl(void);
SSL_CTX *new_server_ctx(char *cert, char *pkey);

#endif /* _SKEETER_SSL_H */

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ldap.h>

#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/dns.h>

#include "io_handler.h"

#define xliteral(a) #a
#define literal(a) xliteral(a)
#define ldap_host "ldap.columbia.edu"
//#define ldap_host "localhost"
#define ldap_port 389
#define ldap_uri "ldap://" ldap_host ":" literal(ldap_port)

//#include "ldap_pvt.h"
int ldap_init_fd(ber_socket_t fd, int proto, LDAP_CONST char *url, LDAP **ldp );

static struct timeval poll_time = {0, 0};

void readcb(struct bufferevent *bev, void *ctx);
void eventcb(struct bufferevent *bev, short events, void *ctx);

int main() {
    LDAP *ld;
    int msgid, rc;
    Sockbuf *sb;

    struct event_base *base;
    struct evdns_base *dnsbase;
    struct bufferevent *bev;

    base = event_base_new();
    dnsbase = evdns_base_new(base, DNS_OPTIONS_ALL);

    bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    bufferevent_socket_connect_hostname(bev, dnsbase, AF_UNSPEC, ldap_host, ldap_port);
    evdns_base_free(dnsbase, 0);

    //rc = ldap_initialize(&ld, "ldap://ldap.columbia.edu");
    rc = ldap_init_fd(bufferevent_getfd(bev), 4, ldap_uri, &ld);
    if (rc)
        return rc;

    ldap_get_option(ld, LDAP_OPT_SOCKBUF, &sb);
    if (sb == NULL) {
        fprintf(stderr, "Could not retrieve sockbuf\n");
        return 1;
    }

    rc = ber_sockbuf_add_io(sb, &ber_sockbuf_io_libevent, LBER_SBIOD_LEVEL_PROVIDER, bev);
    if (rc) {
        fprintf(stderr, "Could not install sockbuf handler");
        return 1;
    }
    bufferevent_setcb(bev, readcb, NULL, eventcb, ld);

    errno = 0;
    rc = ldap_search_ext(ld,
            "", LDAP_SCOPE_BASE,
            NULL, NULL, 0,
            NULL, NULL,
            NULL, 0, &msgid);

    if (rc) {
        printf( "error during search: %s\n", ldap_err2string(rc) );
        return rc;
    }
    printf( "The message ID was %d\n", msgid );

    event_base_dispatch(base);
    event_base_free(base);

    /*
    do {
        //msgtype = ldap_result( ld, LDAP_RES_ANY, 0, &poll_time, &res );
        msgtype = ldap_result( ld, LDAP_RES_ANY, 0, NULL, &res );
        if ( msgtype < 0 ) {
            printf( "error obtaining result\n" );
            return 1;
        }

        msgtype = ldap_msgtype(res);
        printf( "read a message of type 0x%x, msgid %d\n", msgtype, ldap_msgid(res) );

        ldap_msgfree( res );
    } while ( msgtype == LDAP_RES_SEARCH_ENTRY );
    */
    
    return 0;
}

void readcb(struct bufferevent *bev, void *ctx)
{
    LDAP *ld = ctx;
    LDAPMessage *res;
    int msgtype;

    printf( "A read callback!\n" );
    while ( (msgtype = ldap_result( ld, LDAP_RES_ANY, 0, &poll_time, &res )) != 0 ) {
        if ( msgtype < 0 ) {
            printf( "error obtaining result\n" );
        }

        if ( msgtype < 0 || msgtype == LDAP_RES_SEARCH_RESULT )
        {
            printf( "Unbinding\n" );
            ldap_unbind_ext(ld, NULL, NULL);
            // there should be no more reads after this
            // we couldn't handle them anyway with a freed LDAP*
            bufferevent_disable(bev, EV_READ);
            break;
        }

        printf( "read a message of type 0x%x, msgid %d\n", msgtype, ldap_msgid(res) );

        ldap_msgfree( res );
    }

    printf( "No more messages\n" );
}

void eventcb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_CONNECTED) {
        printf("connected\n");
        return;
    }
    printf( "something happened\n" );
    if (events & BEV_EVENT_EOF) {
        /* Connection has been closed and we are done */
    } else {
        printf("Maybe error?\n");
        /* Nothing else has been enabled so this must be an error */
    }
    bufferevent_free(bev);
}

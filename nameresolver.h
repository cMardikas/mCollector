
/*
 * nameresolver.h — mDNS + LLMNR responder module
 *
 * Responds to:
 *   - mDNS queries for "<name>.local" on 224.0.0.251:5353  (RFC 6762)
 *   - LLMNR queries for "<name>" on 224.0.0.252:5355       (RFC 4795)
 *
 * Integration: call nr_init() at startup, nr_poll() from your event loop,
 *              and nr_cleanup() at shutdown.
 *
 * Requires: mdns.h from https://github.com/mjansson/mdns
 */

#ifndef NAMERESOLVER_H
#define NAMERESOLVER_H

/*
 * Initialize the name resolver.
 *   hostname — the name to respond to (e.g. "mytt")
 *              mDNS will answer "<hostname>.local"
 *              LLMNR will answer "<hostname>"
 *
 * Returns 0 on success, -1 if no sockets could be opened.
 */
int nr_init(const char *hostname);

/*
 * Poll all name-resolution sockets (non-blocking).
 * Call this regularly from your main event loop.
 */
void nr_poll(void);

/*
 * Close all sockets and free resources.
 */
void nr_cleanup(void);

#endif /* NAMERESOLVER_H */


/*
 * Minimal libsrt message-mode echo server for the duplex interop test:
 * accepts ONE connection on the given port and echoes every received message
 * back on the same SRT connection (live/message mode — `srt-tunnel` cannot be
 * used for this: it is stream-API only and rejects message-API peers).
 *
 * Built on demand by `interop_edge.rs` against the `~/dev/srt/_build` library.
 */
#include <srt.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);

    srt_startup();
    SRTSOCKET ls = srt_create_socket();
    int latency = 120;
    srt_setsockopt(ls, 0, SRTO_RCVLATENCY, &latency, sizeof latency);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (srt_bind(ls, (struct sockaddr *)&sa, sizeof sa) == SRT_ERROR) {
        fprintf(stderr, "srt_bind: %s\n", srt_getlasterror_str());
        return 1;
    }
    if (srt_listen(ls, 1) == SRT_ERROR) {
        fprintf(stderr, "srt_listen: %s\n", srt_getlasterror_str());
        return 1;
    }

    struct sockaddr_storage peer;
    int plen = sizeof peer;
    SRTSOCKET s = srt_accept(ls, (struct sockaddr *)&peer, &plen);
    if (s == SRT_INVALID_SOCK) {
        fprintf(stderr, "srt_accept: %s\n", srt_getlasterror_str());
        return 1;
    }

    char buf[2048];
    for (;;) {
        int n = srt_recvmsg(s, buf, sizeof buf);
        if (n <= 0)
            break;
        if (srt_sendmsg(s, buf, n, -1, 1) == SRT_ERROR)
            break;
    }
    srt_close(s);
    srt_close(ls);
    srt_cleanup();
    return 0;
}

/*
 * In-process nginx environment shared by the fuzz harnesses.
 *
 * It boots a real ngx_cycle from a baked-in configuration that enables
 * nginx-module-vts, then pushes bytes through the real HTTP pipeline on a
 * fake client connection.  Only the operating system is mocked: bind() and
 * listen() succeed without touching the network, connect() hands nginx a
 * socketpair that already holds an upstream response, and the client
 * connection reads its request from memory and discards what nginx sends.
 * The VTS shared memory is rewound to a post-boot snapshot before every input, and the
 * heap-resident upstream peer state, the connection counter and the clock are reset to boot
 * values: while an input runs, the wall and monotonic clocks nginx and VTS read are a fixed epoch
 * that advances by a fixed step per event-loop round, so an input behaves the same early or late in
 * a process and on any machine.
 */

#ifndef MAYHEM_VTS_ENV_H
#define MAYHEM_VTS_ENV_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

#include "ngx_http_vhost_traffic_status_module.h"
#include "ngx_http_vhost_traffic_status_dump.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ftw.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

extern ngx_module_t  ngx_http_vhost_traffic_status_module;
extern char        **ngx_os_argv;

#define VTS_UPSTREAM_MARK      "\n\001UP\001\n"
#define VTS_UPSTREAM_MARK_LEN  (sizeof(VTS_UPSTREAM_MARK) - 1)
#define VTS_UPSTREAM_MAX       65536
#define VTS_MAX_PAIRS          8

/* the clock an input sees (it starts just after the dump written by the seed corpus) */
#define VTS_EPOCH_SEC          1794384960L
#define VTS_MONO_EPOCH_MS      3600000L
#define VTS_TICK_MS            7L

typedef struct {
    u_char  *addr;
    size_t   size;
    u_char  *snap;
} vts_shm_snapshot_t;

static char                 vts_prefix[128];
static char                *vts_argv[] = { (char *) "nginx", NULL };
static ngx_cycle_t         *vts_cycle;
static ngx_connection_t    *vts_conn;
static const u_char        *vts_req;
static size_t               vts_req_len, vts_req_pos;
static int                  vts_client_eof;
static const u_char        *vts_up;
static size_t               vts_up_len;
static int                  vts_pairs[VTS_MAX_PAIRS];
static int                  vts_npairs;
static int                  vts_trace;
static vts_shm_snapshot_t  *vts_snaps;
static ngx_uint_t           vts_nsnaps;
static int                  vts_clock_on;
static int                  vts_clock_step;
static long                 vts_clock_tick;

extern int __real_gettimeofday(struct timeval *tv, void *tz);
extern int __real_clock_gettime(clockid_t clk, struct timespec *ts);

/* the operating-system mocks: nothing here replaces any nginx or module code */

/* Wall clock (gettimeofday: ngx_time_update, VTS's current_msec) and CLOCK_MONOTONIC
 * (ngx_current_msec) are fixed while an input runs; the clocks the fuzzing engine reads between
 * inputs stay real. */
int
__wrap_gettimeofday(struct timeval *tv, void *tz)
{
    long  ms;

    if (!vts_clock_on) {
        return __real_gettimeofday(tv, tz);
    }

    ms = vts_clock_step ? vts_clock_tick * VTS_TICK_MS : 0;
    tv->tv_sec = VTS_EPOCH_SEC + ms / 1000;
    tv->tv_usec = (ms % 1000) * 1000;

    return 0;
}


int
__wrap_clock_gettime(clockid_t clk, struct timespec *ts)
{
    long  ms;

    if (!vts_clock_on || clk != CLOCK_MONOTONIC) {
        return __real_clock_gettime(clk, ts);
    }

    ms = VTS_MONO_EPOCH_MS + (vts_clock_step ? vts_clock_tick * VTS_TICK_MS : 0);
    ts->tv_sec = ms / 1000;
    ts->tv_nsec = (ms % 1000) * 1000000L;

    return 0;
}


int
__wrap_bind(int fd, const struct sockaddr *addr, socklen_t len)
{
    (void) fd; (void) addr; (void) len;
    return 0;
}


int
__wrap_listen(int fd, int backlog)
{
    (void) fd; (void) backlog;
    return 0;
}


int
__wrap_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    int  sv[2];

    (void) addr; (void) len;

    if (vts_up_len == 0 || vts_npairs >= VTS_MAX_PAIRS) {
        errno = ECONNREFUSED;
        return -1;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        errno = ECONNREFUSED;
        return -1;
    }

    if (write(sv[1], vts_up, vts_up_len) < 0) {
        /* the socket buffer is smaller than the response; keep what fits */
    }

    shutdown(sv[1], SHUT_WR);
    vts_pairs[vts_npairs++] = sv[1];

    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    dup2(sv[0], fd);
    close(sv[0]);

    return 0;
}


static ssize_t
vts_client_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    size_t  n;

    n = vts_req_len - vts_req_pos;

    if (n == 0) {
        if (vts_client_eof) {
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;
        }

        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (n > size) {
        n = size;
    }

    ngx_memcpy(buf, vts_req + vts_req_pos, n);
    vts_req_pos += n;
    c->read->ready = 1;

    return (ssize_t) n;
}


static ssize_t
vts_client_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    (void) c; (void) buf;
    return (ssize_t) size;
}


static ngx_chain_t *
vts_client_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    off_t  sent;

    (void) limit;

    for (sent = 0; in != NULL; in = in->next) {
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        if (ngx_buf_in_memory(in->buf)) {
            if (vts_trace) {
                fwrite(in->buf->pos, 1, in->buf->last - in->buf->pos, stderr);
            }

            sent += in->buf->last - in->buf->pos;
            in->buf->pos = in->buf->last;

        } else {
            sent += in->buf->file_last - in->buf->file_pos;
            in->buf->file_pos = in->buf->file_last;
        }
    }

    c->sent += sent;

    return NULL;
}


static void
vts_stat_reset(void)
{
    *ngx_stat_accepted = 0;
    *ngx_stat_handled = 0;
    *ngx_stat_requests = 0;
    *ngx_stat_active = 0;
    *ngx_stat_reading = 0;
    *ngx_stat_writing = 0;
    *ngx_stat_waiting = 0;
}


static void
vts_snapshot_take(void)
{
    ngx_uint_t       i, n;
    ngx_list_part_t *part;
    ngx_shm_zone_t  *z;

    n = 0;
    for (part = &vts_cycle->shared_memory.part; part; part = part->next) {
        n += part->nelts;
    }

    vts_snaps = calloc(n, sizeof(vts_shm_snapshot_t));
    vts_nsnaps = 0;

    for (part = &vts_cycle->shared_memory.part; part; part = part->next) {
        z = part->elts;
        for (i = 0; i < part->nelts; i++) {
            vts_snaps[vts_nsnaps].addr = z[i].shm.addr;
            vts_snaps[vts_nsnaps].size = z[i].shm.size;
            vts_snaps[vts_nsnaps].snap = malloc(z[i].shm.size);
            memcpy(vts_snaps[vts_nsnaps].snap, z[i].shm.addr, z[i].shm.size);
            vts_nsnaps++;
        }
    }
}


static void
vts_snapshot_restore(void)
{
    ngx_uint_t  i;

    for (i = 0; i < vts_nsnaps; i++) {
        memcpy(vts_snaps[i].addr, vts_snaps[i].snap, vts_snaps[i].size);
    }
}


/* the round-robin peers live in the cycle pool (no upstream zone), so the snapshot
 * does not cover them: put every peer back in its freshly-configured state */
static void
vts_upstreams_reset(void)
{
    ngx_uint_t                       i;
    ngx_http_upstream_main_conf_t   *umcf;
    ngx_http_upstream_srv_conf_t   **uscfp;
    ngx_http_upstream_rr_peers_t    *peers;
    ngx_http_upstream_rr_peer_t     *peer;

    umcf = ngx_http_cycle_get_module_main_conf(vts_cycle,
                                               ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        for (peers = uscfp[i]->peer.data; peers; peers = peers->next) {
            for (peer = peers->peer; peer; peer = peer->next) {
                peer->fails = 0;
                peer->checked = 0;
                peer->accessed = 0;
                peer->conns = 0;
                peer->current_weight = 0;
                peer->effective_weight = peer->weight;
            }
        }
    }
}


static void
vts_pairs_close(void)
{
    while (vts_npairs > 0) {
        close(vts_pairs[--vts_npairs]);
    }
}


static void
vts_pump(int rounds)
{
    int             r;
    ngx_uint_t      i;
    ngx_event_t    *ev;
    ngx_connection_t *c;

    for (r = 0; r < rounds; r++) {
        vts_clock_tick++;
        ngx_time_update();

        ngx_event_process_posted(vts_cycle, &ngx_posted_next_events);
        ngx_event_process_posted(vts_cycle, &ngx_posted_events);

        for (i = 0; i < vts_cycle->connection_n; i++) {
            c = &vts_cycle->connections[i];

            if (c->fd == (ngx_socket_t) -1 || c->read == NULL) {
                continue;
            }

            if (c->listening != NULL && c != vts_conn && c->read->accept) {
                continue;
            }

            ev = c->write;
            if (ev->active && ev->handler != NULL && !ev->closed) {
                ev->ready = 1;
                ev->handler(ev);
                if (c->fd == (ngx_socket_t) -1) {
                    continue;
                }
            }

            ev = c->read;
            if (ev->active && ev->handler != NULL && !ev->closed) {
                ev->ready = 1;
                ev->available = 1;
                ev->handler(ev);
            }
        }

        ngx_event_process_posted(vts_cycle, &ngx_posted_next_events);
        ngx_event_process_posted(vts_cycle, &ngx_posted_events);
    }
}


/* one client connection carrying `req`; upstream peers answer with `up` */
static void
vts_serve(const u_char *req, size_t req_len, const u_char *up, size_t up_len)
{
    int                 s;
    ngx_log_t          *log;
    ngx_connection_t   *c;
    ngx_listening_t    *ls;
    struct sockaddr_in *sin;

    ls = vts_cycle->listening.elts;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        return;
    }

    c = ngx_get_connection(s, vts_cycle->log);
    if (c == NULL) {
        close(s);
        return;
    }

    vts_conn = c;
    vts_req = req;
    vts_req_len = req_len;
    vts_req_pos = 0;
    vts_client_eof = 0;
    vts_up = up;
    vts_up_len = up_len;

    c->type = SOCK_STREAM;
    c->pool = ngx_create_pool(ls->pool_size, vts_cycle->log);
    c->sockaddr = ngx_palloc(c->pool, sizeof(struct sockaddr_in));
    sin = (struct sockaddr_in *) c->sockaddr;
    ngx_memzero(sin, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(54321);
    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    c->socklen = sizeof(struct sockaddr_in);

    log = ngx_palloc(c->pool, sizeof(ngx_log_t));
    *log = ls->log;

    c->recv = vts_client_recv;
    c->send = vts_client_send;
    c->send_chain = vts_client_send_chain;
    c->recv_chain = NULL;
    c->log = log;
    c->pool->log = log;
    c->listening = ls;
    c->local_sockaddr = ls->sockaddr;
    c->local_socklen = ls->socklen;

    c->write->ready = 1;
    c->read->log = log;
    c->write->log = log;
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
    c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                     c->addr_text.data,
                                     ls->addr_text_max_len, 0);

    if (ngx_add_conn && ngx_add_conn(c) == NGX_ERROR) {
        ngx_close_connection(c);
        return;
    }

    log->data = NULL;
    log->handler = NULL;

    (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
    (void) ngx_atomic_fetch_add(ngx_stat_active, 1);

    ls->handler(c);

    /* the client keeps its socket open while nginx works, then hangs up */
    vts_pump(8);

    vts_client_eof = 1;
    c->read->ready = 1;
    vts_pump(8);

    if (vts_trace) {
        fprintf(stderr, "\n[vts] connection %s\n",
                c->fd == (ngx_socket_t) -1 ? "closed" : "STILL OPEN");
    }
}


/* a request whose upstream (if the location proxies) answers `up` */
static void
vts_serve_split(const u_char *data, size_t size)
{
    size_t        i;
    const u_char *up = NULL;
    size_t        up_len = 0, req_len = size;

    for (i = 0; i + VTS_UPSTREAM_MARK_LEN <= size; i++) {
        if (memcmp(data + i, VTS_UPSTREAM_MARK, VTS_UPSTREAM_MARK_LEN) == 0) {
            req_len = i;
            up = data + i + VTS_UPSTREAM_MARK_LEN;
            up_len = size - i - VTS_UPSTREAM_MARK_LEN;
            if (up_len > VTS_UPSTREAM_MAX) {
                up_len = VTS_UPSTREAM_MAX;
            }
            break;
        }
    }

    vts_serve(data, req_len, up, up_len);
}


static void
vts_input_begin(void)
{
    vts_pairs_close();
    vts_snapshot_restore();
    vts_upstreams_reset();
    vts_stat_reset();
    *ngx_connection_counter = 1;

    vts_clock_on = 1;
    vts_clock_tick = 0;
    ngx_time_update();
}


static void
vts_input_end(void)
{
    vts_pairs_close();
    vts_clock_on = 0;
}


static void
vts_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
}


static const char vts_conf_fmt[] =
    "daemon off;\n"
    "master_process off;\n"
    "worker_processes 1;\n"
    "error_log /dev/null emerg;\n"
    "pid %1$s/nginx.pid;\n"
    "events { worker_connections 64; use epoll; }\n"
    "http {\n"
    "  access_log off;\n"
    "  sendfile off;\n"
    "  client_body_temp_path %1$s/body;\n"
    "  proxy_temp_path %1$s/proxy;\n"
    "  client_body_buffer_size 256k;\n"
    "  vhost_traffic_status_zone shared:vts:1m;\n"
    "  vhost_traffic_status_dump %1$s/vts.dump 1s;\n"
    "  vhost_traffic_status_filter_by_set_key $http_user_agent agent::$server_name;\n"
    "  vhost_traffic_status_filter_max_node 8 agent::;\n"
    "  vhost_traffic_status_average_method WMA 30s;\n"
    "  vhost_traffic_status_histogram_buckets 0.005 0.05 0.5 5;\n"
    "  vhost_traffic_status_measure_status_codes all;\n"
    "  upstream backend {\n"
    "    server 127.0.0.1:9 weight=2;\n"
    "    server unix:%1$s/up.sock;\n"
    "    server 127.0.0.1:10 backup;\n"
    "  }\n"
    "  server {\n"
    "    listen 127.0.0.1:8080;\n"
    "    server_name example.com *.example.com;\n"
    "    root %1$s/html;\n"
    "    vhost_traffic_status_filter_by_host on;\n"
    "    location /status {\n"
    "      vhost_traffic_status_display;\n"
    "      vhost_traffic_status_display_format html;\n"
    "      vhost_traffic_status_bypass_stats on;\n"
    "      vhost_traffic_status_display_sum_key total;\n"
    "      access_log off;\n"
    "    }\n"
    "    location /status/format/jsonp {\n"
    "      vhost_traffic_status_display;\n"
    "      vhost_traffic_status_display_format jsonp;\n"
    "      vhost_traffic_status_display_jsonp cb;\n"
    "    }\n"
    "    location /proxy/ { proxy_pass http://backend; proxy_next_upstream error timeout http_502; }\n"
    "    location /direct/ { proxy_pass http://127.0.0.1:9/; }\n"
    "    location /limited/ {\n"
    "      vhost_traffic_status_limit_traffic request:2k 429;\n"
    "      vhost_traffic_status_limit_traffic_by_set_key $http_x_key out:1m;\n"
    "    }\n"
    "    location /ignored/ { vhost_traffic_status_ignore_status 4xx 5xx; }\n"
    "  }\n"
    "  server {\n"
    "    listen 127.0.0.1:8080;\n"
    "    server_name other.test;\n"
    "    root %1$s/html;\n"
    "    vhost_traffic_status off;\n"
    "  }\n"
    "}\n";


static int
vts_rm_entry(const char *path, const struct stat *sb, int type, struct FTW *ftw)
{
    (void) sb; (void) type; (void) ftw;
    return remove(path);
}


static void
vts_cleanup(void)
{
    nftw(vts_prefix, vts_rm_entry, 8, FTW_DEPTH | FTW_PHYS);
}


/* Last-Modified, ETag and If-Modified-Since depend on the file's mtime: pin it */
static void
vts_fix_mtime(const char *path)
{
    struct timespec  ts[2];

    ts[0].tv_sec = ts[1].tv_sec = VTS_EPOCH_SEC - 3600;
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    utimensat(AT_FDCWD, path, ts, 0);
}


static void
vts_boot(void)
{
    char                 path[256], conf[4096];
    const char          *tmp;
    ngx_log_t           *log;
    ngx_cycle_t          init_cycle;
    ngx_uint_t           i;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    tmp = getenv("TMPDIR");
    if (tmp == NULL || tmp[0] == '\0') {
        tmp = "/tmp";
    }

    if (snprintf(vts_prefix, sizeof(vts_prefix), "%s/vts-fuzz-XXXXXX", tmp)
        >= (int) sizeof(vts_prefix)
        || mkdtemp(vts_prefix) == NULL)
    {
        fprintf(stderr, "mkdtemp failed\n");
        exit(1);
    }

    atexit(vts_cleanup);

    snprintf(path, sizeof(path), "%s/html", vts_prefix);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "%s/html/index.html", vts_prefix);
    vts_write_file(path, "<html>vts</html>\n");
    vts_fix_mtime(path);
    snprintf(path, sizeof(path), "%s/nginx.conf", vts_prefix);
    snprintf(conf, sizeof(conf), vts_conf_fmt, vts_prefix);
    vts_write_file(path, conf);

    signal(SIGPIPE, SIG_IGN);
    vts_trace = getenv("VTS_TRACE") != NULL;

    if (ngx_strerror_init() != NGX_OK) {
        exit(1);
    }

    /* configuration time (VTS records its start time) is on the epoch too */
    vts_clock_on = 1;
    vts_clock_step = 0;

    ngx_max_sockets = -1;
    ngx_time_init();
    ngx_pid = ngx_getpid();
    ngx_parent = ngx_getppid();

    snprintf(path, sizeof(path), "%s/", vts_prefix);
    log = ngx_log_init((u_char *) path, (u_char *) "/dev/null");
    if (log == NULL) {
        exit(1);
    }

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    init_cycle.pool = ngx_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        exit(1);
    }

    ngx_os_argv = vts_argv;

    ngx_str_set(&init_cycle.conf_param, "");
    init_cycle.prefix.len = ngx_strlen(path);
    init_cycle.prefix.data = ngx_pstrdup(init_cycle.pool,
                                &(ngx_str_t) { ngx_strlen(path), (u_char *) path });
    init_cycle.conf_prefix = init_cycle.prefix;

    snprintf(path, sizeof(path), "%s/nginx.conf", vts_prefix);
    init_cycle.conf_file.len = ngx_strlen(path);
    init_cycle.conf_file.data = ngx_pstrdup(init_cycle.pool,
                                &(ngx_str_t) { ngx_strlen(path), (u_char *) path });

    if (ngx_os_init(log) != NGX_OK
        || ngx_crc32_table_init() != NGX_OK)
    {
        exit(1);
    }

    ngx_slab_sizes_init();

    if (ngx_preinit_modules() != NGX_OK) {
        exit(1);
    }

    vts_cycle = ngx_init_cycle(&init_cycle);
    if (vts_cycle == NULL) {
        fprintf(stderr, "ngx_init_cycle failed (config %s)\n", path);
        exit(1);
    }

    ngx_cycle = vts_cycle;
    ngx_use_stderr = 0;

    for (i = 0; vts_cycle->modules[i]; i++) {
        if (vts_cycle->modules[i]->init_process
            && vts_cycle->modules[i]->init_process(vts_cycle) == NGX_ERROR)
        {
            fprintf(stderr, "init_process failed\n");
            exit(1);
        }
    }

    ctx = ngx_http_cycle_get_module_main_conf(vts_cycle,
                                    ngx_http_vhost_traffic_status_module);
    if (ctx == NULL || ctx->rbtree == NULL) {
        fprintf(stderr, "vts zone not initialised\n");
        exit(1);
    }

    /* warm the zone so display/control/limit code has nodes to walk */
    {
        static const char warm1[] =
            "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: warm\r\n\r\n";
        static const char warm2[] =
            "GET /missing HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        static const char warm3[] =
            "GET /proxy/x HTTP/1.1\r\nHost: example.com\r\nX-Key: k\r\n\r\n";

        /* the warm-up runs on the epoch itself; inputs advance from it */
        vts_input_begin();
        vts_clock_step = 0;
        vts_serve((const u_char *) warm1, sizeof(warm1) - 1, NULL, 0);
        vts_serve((const u_char *) warm2, sizeof(warm2) - 1, NULL, 0);
        vts_serve((const u_char *) warm3, sizeof(warm3) - 1,
                  (const u_char *) "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", 40);
        vts_input_end();
        vts_clock_step = 1;
    }

    vts_snapshot_take();
}

#endif

/* Fuzzes the dump-file restore parser: the input is the content of the file named
 * by vhost_traffic_status_dump, read back the way a restarting worker does it; the
 * restored zone is then rendered through the display handlers. */
#include "vts_env.h"

static const char req_json[] =
    "GET /status/format/json HTTP/1.1\r\nHost: example.com\r\n\r\n";
static const char req_prom[] =
    "GET /status/format/prometheus HTTP/1.1\r\nHost: example.com\r\n\r\n";


int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc; (void) argv;
    vts_boot();
    return 0;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE                                 *f;
    ngx_http_vhost_traffic_status_ctx_t  *ctx;

    vts_input_begin();

    ctx = ngx_http_cycle_get_module_main_conf(vts_cycle,
                                    ngx_http_vhost_traffic_status_module);

    f = fopen((const char *) ctx->dump_file.data, "wb");
    if (f == NULL) {
        vts_input_end();
        return 0;
    }

    fwrite(data, 1, size, f);
    fclose(f);

    ctx->dump_event.log = vts_cycle->log;
    ctx->dump_event.data = ctx;
    ngx_http_vhost_traffic_status_dump_restore(&ctx->dump_event);

    vts_serve((const u_char *) req_json, sizeof(req_json) - 1, NULL, 0);
    vts_serve((const u_char *) req_prom, sizeof(req_prom) - 1, NULL, 0);

    vts_input_end();
    return 0;
}

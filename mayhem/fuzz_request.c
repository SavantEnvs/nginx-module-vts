/* Fuzzes the whole HTTP request path of nginx with nginx-module-vts loaded:
 * request parsing, the display/control handlers, filter keys, traffic limits,
 * upstream accounting and the log-phase statistics. The input is one client
 * connection's bytes; text after "\n\x01UP\x01\n" is what upstream peers answer. */
#include "vts_env.h"

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
    vts_input_begin();
    vts_serve_split(data, size);
    vts_input_end();
    return 0;
}

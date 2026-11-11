#!/usr/bin/env bash
#
# mayhem/build.sh — builds nginx (pinned source in /opt/toolchains/deps) with nginx-module-vts
# compiled in, twice:
#   1. sanitized + coverage-instrumented, linked with the in-process harnesses under mayhem/
#      -> /mayhem/fuzz_request, /mayhem/fuzz_dump (+ -standalone reproducers)
#   2. with nginx's normal flags -> mayhem/build/normal/nginx, the binary mayhem/test.sh runs.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

: "${SRC:=/mayhem}"
cd "$SRC"

NGX=/opt/toolchains/deps/nginx-1.28.0/src
BUILD=$SRC/mayhem/build
FUZZ=$BUILD/fuzz
NORMAL=$BUILD/normal
mkdir -p "$BUILD"

# Only what the harness configuration and the oracle need. The request path, upstream (proxy) module,
# static files and every VTS source file are all kept.
NGX_CONFIGURE=(
  --with-cc="$CC"
  --without-pcre --without-http_rewrite_module --without-http_gzip_module
  --without-http_fastcgi_module --without-http_uwsgi_module --without-http_scgi_module
  --without-http_ssi_module --without-http_userid_module --without-http_autoindex_module
  --without-http_auth_basic_module --without-http_geo_module --without-http_map_module
  --without-http_split_clients_module --without-http_referer_module
  --without-http_memcached_module --without-http_limit_conn_module
  --without-http_limit_req_module --without-http_empty_gif_module
  --without-http_browser_module --without-http_upstream_hash_module
  --without-http_upstream_ip_hash_module --without-http_upstream_least_conn_module
  --without-http_upstream_random_module --without-http_upstream_keepalive_module
  --without-http_upstream_zone_module
  --add-module="$SRC"
)

# nginx must be configured and made from its own source directory (it is read-only here, and
# only writes into the --builddir). LeakSanitizer is off for configure's probe programs.
configure_nginx() {  # builddir cc-opt ld-opt
  mkdir -p "$1"
  ( cd "$NGX" && ASAN_OPTIONS=detect_leaks=0 ./configure --builddir="$1" "${NGX_CONFIGURE[@]}" \
      --with-cc-opt="$2" --with-ld-opt="$3" >"$1/configure.log" 2>&1 ) \
    || { tail -30 "$1/configure.log" >&2; exit 1; }
  ( cd "$NGX" && make -f "$1/Makefile" -j"$MAYHEM_JOBS" )
}

# 1) the normal-flags build the oracle runs (built first; the sanitized build never touches it)
configure_nginx "$NORMAL" "-O2 $COVERAGE_FLAGS" "$COVERAGE_FLAGS"

# 2) sanitized + instrumented build. -DNGX_DEBUG_PALLOC=1 turns every pool allocation into a
# malloc so ASan sees overflows in pool memory. nginx loads and casts through unaligned/mistyped
# pointers on purpose (ngx_str*_cmp, ngx_http_*_filter handlers), which would flood UBSan:
# only `alignment`, `function` and `nonnull-attribute` (nginx and VTS call memcpy(dst, NULL, 0) for empty ngx_str_t) are relaxed; everything else stays halting.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link -fno-sanitize=function,alignment,nonnull-attribute $DEBUG_FLAGS"
configure_nginx "$FUZZ" "$FUZZ_CFLAGS -O1 -DNGX_DEBUG_PALLOC=1" "$SANITIZER_FLAGS"

# nginx.o defines main(); the harness supplies its own entry point.
H=$BUILD/harness
mkdir -p "$H"
objcopy --redefine-sym main=nginx_orig_main "$FUZZ/src/core/nginx.o" "$H/nginx_nomain.o"
mapfile -t OBJS < <(find "$FUZZ/src" "$FUZZ/addon" -name '*.o' ! -name nginx.o | LC_ALL=C sort)
OBJS+=("$FUZZ/ngx_modules.o" "$H/nginx_nomain.o")

INCS=(-I"$NGX/src/core" -I"$NGX/src/event" -I"$NGX/src/event/modules" -I"$NGX/src/os/unix"
      -I"$FUZZ" -I"$NGX/src/http" -I"$NGX/src/http/modules" -I"$SRC/src")

# LeakSanitizer is off at build time (the fleet's fuzz targets look for memory corruption, not leaks).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$H/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$H/standalone_main.o"

# bind/listen/connect/gettimeofday/clock_gettime are the only mocked calls: no sockets are opened,
# upstream connects hand nginx a socketpair carrying the upstream response taken from the input, and
# the clocks nginx and VTS read are a fixed per-input epoch (so an input's result does not depend on
# when in the process, or on which machine, it runs).
WRAP=(-Wl,--wrap=bind -Wl,--wrap=listen -Wl,--wrap=connect
      -Wl,--wrap=gettimeofday -Wl,--wrap=clock_gettime -Wl,-E)
LIBS=(-ldl -lpthread -lcrypt -lm)

for t in fuzz_request fuzz_dump; do
  $CC $FUZZ_CFLAGS -O1 -DNGX_DEBUG_PALLOC=1 "${INCS[@]}" -c "$SRC/mayhem/$t.c" -o "$H/$t.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${WRAP[@]}" \
      "$H/$t.o" "${OBJS[@]}" "$H/lsan_off.o" "${LIBS[@]}" -o "$SRC/$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${WRAP[@]}" \
      "$H/$t.o" "$H/standalone_main.o" "${OBJS[@]}" "$H/lsan_off.o" "${LIBS[@]}" -o "$SRC/$t-standalone"
done

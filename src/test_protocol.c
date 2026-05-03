/* Unit tests for protocol framing helpers and replay window. */

#include "protocol.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (msg)); failures++; } \
    else fprintf(stderr, "  ok: %s\n", (msg)); \
} while (0)

static void test_be_helpers(void) {
    uint8_t buf[8];
    pq_store_be32(buf, 0xDEADBEEFu);
    CHECK(pq_load_be32(buf) == 0xDEADBEEFu, "be32 round-trip");

    pq_store_be64(buf, 0x0123456789ABCDEFull);
    CHECK(pq_load_be64(buf) == 0x0123456789ABCDEFull, "be64 round-trip");
}

static void test_window_basic(void) {
    pq_replay_window_t w; pq_replay_init(&w);

    CHECK(pq_replay_check_and_update(&w, 1) == true,  "fresh seq=1");
    CHECK(pq_replay_check_and_update(&w, 2) == true,  "fresh seq=2");
    CHECK(pq_replay_check_and_update(&w, 1) == false, "duplicate seq=1");
    CHECK(pq_replay_check_and_update(&w, 5) == true,  "skip ahead seq=5");
    CHECK(pq_replay_check_and_update(&w, 3) == true,  "out-of-order seq=3 within window");
    CHECK(pq_replay_check_and_update(&w, 3) == false, "duplicate seq=3");
}

static void test_window_too_old(void) {
    pq_replay_window_t w; pq_replay_init(&w);
    pq_replay_check_and_update(&w, 100);
    CHECK(pq_replay_check_and_update(&w, 30) == false, "seq=30 too old (>64 behind 100)");
    CHECK(pq_replay_check_and_update(&w, 50) == true,  "seq=50 within window");
}

int main(void) {
    test_be_helpers();
    test_window_basic();
    test_window_too_old();
    if (failures == 0) {
        fprintf(stderr, "ALL OK\n");
        return 0;
    }
    fprintf(stderr, "%d failures\n", failures);
    return 1;
}

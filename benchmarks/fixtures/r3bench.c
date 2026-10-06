#include <stdint.h>
#include <stdio.h>

static const char marker_a[] = "RADARE3_SEARCH_MARKER_ALPHA";
static const char marker_b[] = "RADARE3_SEARCH_MARKER_BETA";
static const uint16_t wide_marker[] = {
    'R','A','D','A','R','E','3','_','W','I','D','E','_','M','A','R','K','E','R',0
};

static volatile uint64_t sink;

__attribute__((noinline))
static uint64_t mix(uint64_t value) {
    for (uint64_t i = 0; i < 64; ++i) {
        if ((value ^ i) & 1) {
            value = (value * 0x9e3779b185ebca87ULL) ^ (value >> 7);
        } else {
            value = (value + 0x517cc1b727220a95ULL) ^ (value << 11);
        }
    }
    return value;
}

__attribute__((noinline))
static uint64_t dispatch(uint64_t value) {
    switch (value & 7) {
        case 0: return mix(value + 1);
        case 1: return mix(value + 3);
        case 2: return mix(value + 5);
        case 3: return mix(value + 7);
        case 4: return mix(value + 11);
        case 5: return mix(value + 13);
        case 6: return mix(value + 17);
        default: return mix(value + 19);
    }
}

int main(int argc, char **argv) {
    uint64_t value = (uint64_t)argc;
    for (uint64_t i = 0; i < 2048; ++i) {
        value ^= dispatch(value + i);
    }

    sink = value + marker_a[0] + marker_b[1] + wide_marker[2];
    if (argv != NULL && argv[0] != NULL && argv[0][0] == '\0') {
        puts(marker_a);
    }

    printf("%llu\n", (unsigned long long)sink);
    return 0;
}

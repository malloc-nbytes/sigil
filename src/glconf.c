#include <stdint.h>
#include <stddef.h>

struct {
        uint32_t flags;
        struct {
                size_t w;
                size_t h;
        } term;
} glconf = {
        .flags = 0x0000,
        .term = {
                .w = 0,
                .h = 0,
        },
};

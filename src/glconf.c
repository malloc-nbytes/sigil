#include <stdint.h>
#include <stddef.h>
#include <termios.h>

struct {
        uint32_t flags;
        char config_filepath[512];
        struct {
                size_t w;
                size_t h;
                struct termios old;
        } term;
} glconf = {
        .flags = 0x0000,
        .config_filepath = {0},
        .term = {
                .w = 0,
                .h = 0,
                .old = {0},
        },
};

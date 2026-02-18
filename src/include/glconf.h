#ifndef GLCONF_H_INCLUDED
#define GLCONF_H_INCLUDED

#include "qcl.h"

#include <stddef.h>
#include <stdint.h>
#include <termios.h>

extern struct {
        uint32_t flags;
        char config_filepath[512];
        struct {
                int space_amt;
                const char *compile_cmd;
        } defaults;
        struct {
                size_t w;
                size_t h;
                struct termios old;
        } term;
} glconf;

#endif // GLCONF_H_INCLUDED

#ifndef GLCONF_H_INCLUDED
#define GLCONF_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

extern struct {
        uint32_t flags;
        struct {
                size_t w;
                size_t h;
        } term;
} glconf;

#endif // GLCONF_H_INCLUDED

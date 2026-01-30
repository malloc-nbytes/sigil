#ifndef WINDOW_H_INCLUDED
#define WINDOW_H_INCLUDED

#include "buffer.h"

#include <stddef.h>

typedef struct {
        buffer *ab;
        size_t  w;
        size_t  h;
} window;

#endif // WINDOW_H_INCLUDED

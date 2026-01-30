#ifndef BUFFER_H_INUCLUDED
#define BUFFER_H_INUCLUDED

#include "line.h"
#include "str.h"

#include <stddef.h>

typedef struct {
        str          filename;
        line_array   lns;
        size_t       cx;
        size_t       cy;
        line       **al;
} buffer;

buffer *buffer_alloc(void);
buffer *buffer_from_file(str filename);

#endif // BUFFER_H_INUCLUDED

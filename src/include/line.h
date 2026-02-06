#ifndef LINE_H_INCLUDED
#define LINE_H_INCLUDED

#include "array.h"
#include "str.h"

typedef struct {
        str s;
} line;

DYN_ARRAY_TYPE(line *, line_array);

line       *line_alloc();
line       *line_from(str s);
line       *line_from_cstr(const char *s);
line_array  lines_of_cstr(const char *s);
void        line_free(line *ln);

#endif // LINE_H_INCLUDED

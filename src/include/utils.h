#ifndef UTILS_H_INCLUDED
#define UTILS_H_INCLUDED

#define MIN(a, b) (a) <= (b) ? (a) : (b)

int doregex(const char *pattern, const char *s);
int cstr_isdigit(const char *s);

#endif // UTILS_H_INCLUDED

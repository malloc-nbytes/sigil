#ifndef FLAGS_H_INCLUDED
#define FLAGS_H_INCLUDED

#define CONFIG_FILENAME ".wwrc"
#define DEFAULT_SPACE_AMT 8
#define DEFAULT_COMPILE_COMMAND "make"

enum {
        FT_SHOWTRAILS = 1 << 0,
        FT_SPACESARETABS = 1 << 1,
};

void usage(void);

#endif // FLAGS_H_INCLUDED

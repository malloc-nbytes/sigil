#include "argument.h"
#include "flags.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static void
run(const char *filename)
{
        assert(0);
}

int
main(int argc, char *argv[])
{
        char *filename;

        if (argc <= 1)
                usage();

        filename = parse_args(argc, argv);
        run(filename);
        free(filename);

        return 0;
}



#include <stdlib.h>

typedef struct _c_struct {
    int a;
    int b;
    int c;
} c_struct;

c_struct* gc_structp;

int foo(c_struct* c_structp)
{
    int to_return  = c_structp->c;

    to_return = to_return + rand();
    to_return = to_return - rand();

    return to_return;
}

__attribute__((constructor)) void cosntructor()
{
    gc_structp = malloc(sizeof(c_struct));

    gc_structp->c = 10;

    int result = foo(gc_structp);

    free(gc_structp);
}
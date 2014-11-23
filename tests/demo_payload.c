#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
void sayhello(void)
{
	fprintf(stdout, "Hello from [%d]\n", getpid());
}

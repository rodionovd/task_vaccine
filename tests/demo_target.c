#include <stdio.h>
#include <dispatch/dispatch.h>

int main(int argc, char const *argv[])
{
	fprintf(stdout, "Target: %d\n", getpid());
	/* Wait for injection */
	dispatch_main();

	return 0;
}

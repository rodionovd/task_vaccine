#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include "../task_vaccine.h"
#include "../submodules/Cegta/Cegta.h"

task_t _launch_target(const char *label);
void _kill_target(task_t target);


SpecBegin(task_vaccine)

describe("i386 target", ^{
	__block task_t target = (-1);

	beforeEach(^(const char *it) {
		target = _launch_target("./build/target.i386");
	});

	afterEach(^(const char *it) {
		_kill_target(target);
	});

	it("should be injected with i386 payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build/payload.i386");
		expectInt(err, toBe(KERN_SUCCESS));
	});
	it("should be injected with FAT payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build/payload.i386.x86_64");
		expectInt(err, toBe(KERN_SUCCESS));
	});
	it("should NOT be injected with x86_64 payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build/payload.x86_64");
		expectInt(err, toBe(KERN_INVALID_TASK));
	});
});

describe("x86_64 target",^{

	__block task_t target = (-1);

	beforeEach(^(const char *it) {
		target = _launch_target("./build/target.x86_64");
 	});

 	afterEach(^(const char *it) {
 		_kill_target(target);
 	});

	it("should be injected with x86_64 payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build/payload.x86_64");
		expectInt(err, toBe(KERN_SUCCESS));
	});
	it("should be injected with FAT payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build/payload.i386.x86_64");
		expectInt(err, toBe(KERN_SUCCESS));
	});

	it("should NOT be injected with i386 payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build/payload.i386");
		expectInt(err, toBe(KERN_INVALID_TASK));
	});
});

SpecEnd()


CegtaRun();


#pragma mark - Utils

task_t _launch_target(const char *label)
{
	task_t task = (-1);

	pid_t pid = fork();
	if (pid == 0) {
		execl(label, NULL);
		fprintf(stderr, "Unable to execv() the target <%s> due to error: %s\n",
		        label, strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		usleep(60000); // let it initialize a bit
		int err = task_for_pid(mach_task_self(), pid, &task);
		assert(err == KERN_SUCCESS);
	}

	return (task);
}

void _kill_target(task_t target)
{
	pid_t pid;
	int err = pid_for_task(target, &pid);
	assert(err == KERN_SUCCESS);

	kill(pid, SIGTERM);
}

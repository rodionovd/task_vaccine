#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include "../task_vaccine.h"
#include "../submodules/Cegta/Cegta.h"

#define kTargetInitializationTimeMSec 300000

SpecBegin(task_vaccine)

task_t (^_launch_target)(const char *) = ^(const char *target) {
	task_t task = (-1);
	pid_t pid = fork();
	if (pid == 0) {
		execl(target, NULL);
		fprintf(stderr, "Unable to execv() the target <%s> due to error: %s\n",
		        target, strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		usleep(kTargetInitializationTimeMSec); // let it initialize a bit
		int err = task_for_pid(mach_task_self(), pid, &task);
		assert(err == KERN_SUCCESS);
	}
	return (task);
};

void (^_kill_target)(task_t target) = ^(task_t target) {
	pid_t pid;
	int err = pid_for_task(target, &pid);
	assert(err == KERN_SUCCESS);
	kill(pid, SIGTERM);
};

describe("i386 target", ^{
	__block task_t target = (-1);

	beforeEach(^(const char *it) {
		target = _launch_target("./build_tests/target.i386");
	});

	afterEach(^(const char *it) {
		_kill_target(target);
	});

	it("should be injected with i386 payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build_tests/payload.i386");
		expectInt(err, toBe(KERN_SUCCESS));
	});
	it("should be injected with FAT payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build_tests/payload.i386.x86_64");
		expectInt(err, toBe(KERN_SUCCESS));
	});
	it("should NOT be injected with x86_64 payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build_tests/payload.x86_64");
		expectInt(err, toBe(KERN_INVALID_TASK));
	});
});

describe("x86_64 target",^{

	__block task_t target = (-1);

	beforeEach(^(const char *it) {
		target = _launch_target("./build_tests/target.x86_64");
 	});

 	afterEach(^(const char *it) {
 		_kill_target(target);
 	});

	it("should be injected with x86_64 payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build_tests/payload.x86_64");
		expectInt(err, toBe(KERN_SUCCESS));
	});
	it("should be injected with FAT payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build_tests/payload.i386.x86_64");
		expectInt(err, toBe(KERN_SUCCESS));
	});

	it("should NOT be injected with i386 payload", ^{
		requireInt(target, notToBe(-1));

		int err = task_vaccine(target, "./build_tests/payload.i386");
		expectInt(err, toBe(KERN_INVALID_TASK));
	});
});

SpecEnd()


CegtaMain();

## task_vaccine  

[![Build Status](https://travis-ci.org/rodionovd/task_vaccine.svg?branch=master)](https://travis-ci.org/rodionovd/task_vaccine)

Yet another code injection library for OS X.


#### TL;DR

```sh
$ git clone --recursive https://github.com/rodionovd/task_vaccine.git task_vaccine
$ cd ./task_vaccine
$ rake test
$ rake build # will build an x86_64 dynamic library and place it into ./build/x86_64
```

```c
#include "task_vaccine.h"

task_t target = ...;
int err = task_vaccine(target, "./payload0.dylib");
if (err != KERN_SUCCESS) {
    fprintf(stderr, "task_vaccine() failed with error: %d\n", err);
}
```
see [Usage](#usage) for details.


#### Why should I use this thing instead of [`mach_inject`](https://github.com/rentzsch/mach_inject)?
Well, for a couple of reasons actually:

1. `mach_inject`'s codebase is old and it hasn't been updated for a while.
2. You **can not** inject `i386` targets from `x86_64` hosts and vice versa using `mach_inject`, so you should use two different injectors. *With `task_vaccine` you* **can** *actually do it.*
3. I have [automated tests](./tests/Rakefile) 🚦

#### How it works

Pretty straightforward, see:

1. At first, we create a new thread inside a target task (process) and execute `_pthread_set_self()` function on it.

  > We can only create a raw Mach thread inside a target task. But many functions (such as `dlopen()`) rely on pthread stuff (locks, etc), so we have to initialize a pthread first and only then execute `dlopen()` for loading the payload.

2. Then, `_pthread_set_self()` returns into an invalid memory address throwing an `EXC_BAD_ACCESS` exception.
3. We catch this exception and reconfigure the thread to launch `dlopen()` with a given library path. When it returns, one more `EXC_BAD_ACCESS` exception is thrown — we catch 'em as well and terminate the remote thread.
4. We examine a `dlopen()` return value then: if it's greater than zero, `task_vaccine` succeeded.

#### Caveats
As you may have notice `task_vaccine()` takes a `task_t` argument. This means you should obtain a task port of your target first:

```c
pid_t proc = ...;
task_t task;
task_for_pid(mach_task_self(), proc, &task);
```

**Of course, you must have an ability to control other processes (i.e. you should be a member of `procmod` user group. Being root is also OK).**

#### Usage

A prototype for the function is the following:

```c
kern_return_t task_vaccine(task_t target, const char *payload_path);
```

| Parameter   | Type (in/out) | Description |
| :--------: | :-----------: | :---------- |
| `target` | in  | _**(required)**_ An identifier of the target process |
| `payload_path ` | in| _**(required)**_ A full or relative path to the library you want to load into the given target. The library should be compatible with the target task. In order to be meaningful, this library should also contain a constructor function that will be executed on load |


| Return value  |  Description |
| :----------   |  :---------- |
| KERN_SUCCESS | The payload was loaded successfully into the target task |
| KERN_INVALID_TASK | `dlopen()` failed to load the given library (e.g. target architecture doesn't match the payload) |
| KERN_FAILURE | Something gone totally wrong on a `task_vaccine`’s side. Please [open an issue](https://github.com/rodionovd/task_vaccine/issues/new) |

---------

If you found any bug(s) or something, please open an issue or a pull request — I'd appreciate your help! (^,,^)

Dmitry Rodionov, 2014  
i.am.rodionovd@gmail.com

# Taken and adapted from github.com/furnace-dev/furnace

from memory import UnsafePointer, memset_zero, memcpy
from utils import StaticTuple
from sys.ffi import external_call

from websockets.logger import logger

alias THREAD_POOL_SIZE = 10
alias __SIZEOF_PTHREAD_MUTEX_T = 40  # value for x86_64
alias __SIZEOF_PTHREAD_ATTR_T = 56  # value for x86_64

alias PTHREAD_MUTEX_TIMED_NP = 0
alias PTHREAD_MUTEX_RECURSIVE_NP = 1
alias PTHREAD_MUTEX_ERRORCHECK_NP = 2
alias PTHREAD_MUTEX_ADAPTIVE_NP = 3

alias pthread_t = UInt64


# ===-------------------------------------------------------------------=== #
# POSIX Threads
# ===-------------------------------------------------------------------=== #


@value
@register_passable("trivial")
struct __pthread_mutex_s:
    var __lock: Int32
    var __count: UInt32
    var __owner: Int32
    var __nusers: UInt32
    var __kind: Int32
    var __spins: Int16
    var __elision: Int16
    var __list: __pthread_list_t


@value
@register_passable("trivial")
struct pthread_mutex_t:
    var __data: __pthread_mutex_s
    var __size: StaticTuple[Int8, __SIZEOF_PTHREAD_MUTEX_T]
    var __align: Int64

    fn __init__(out self, __kind: Int32):
        self.__data = __pthread_mutex_s(
            0,
            0,
            0,
            0,
            __kind,
            0,
            0,
            __pthread_list_t(),
        )
        self.__size = StaticTuple[Int8, __SIZEOF_PTHREAD_MUTEX_T](0)
        self.__align = 0


@value
@register_passable("trivial")
struct __pthread_list_t:
    # FIXME: __prev and __next should be a pointers to __pthread_list_t
    # but now a void pointer would do which is a Pointer[UInt8]
    var __prev: UnsafePointer[UInt8]
    var __next: UnsafePointer[UInt8]

    fn __init__(out self):
        self.__prev = UnsafePointer[UInt8]()
        self.__next = UnsafePointer[UInt8]()


@value
@register_passable("trivial")
struct pthread_cond_t:
    var __data: __pthread_cond_s
    var __size: StaticTuple[Int8, __SIZEOF_PTHREAD_MUTEX_T]
    var __align: Int64

    fn __init__(out self):
        self.__data = __pthread_cond_s(
            __atomic_wide_counter(
                __value64=0,
                __value32=__value32(
                    __low=0,
                    __high=0,
                ),
            ),
            __atomic_wide_counter(
                __value64=0,
                __value32=__value32(
                    __low=0,
                    __high=0,
                ),
            ),
            StaticTuple[UInt32, 2](0, 0),
            StaticTuple[UInt32, 2](0, 0),
            0,
            0,
            StaticTuple[UInt32, 2](0, 0),
        )
        self.__size = StaticTuple[Int8, __SIZEOF_PTHREAD_MUTEX_T](0)
        self.__align = 0


@value
@register_passable("trivial")
struct __pthread_cond_s:
    var __wseq: __atomic_wide_counter
    var __g1_start: __atomic_wide_counter
    var __g_refs: StaticTuple[UInt32, 2]
    var __g_size: StaticTuple[UInt32, 2]
    var __g1_orig_size: UInt32
    var __wrefs: UInt32
    var __g_signals: StaticTuple[UInt32, 2]


@value
@register_passable("trivial")
struct __atomic_wide_counter:
    var __value64: UInt64
    var __value32: __value32


@value
@register_passable("trivial")
struct __value32:
    var __low: UInt32
    var __high: UInt32


@value
@register_passable("trivial")
struct pthread_attr_t:
    var __size: StaticTuple[UInt8, __SIZEOF_PTHREAD_ATTR_T]
    var __align: Int64

    fn __init__(out self):
        self.__size = StaticTuple[UInt8, __SIZEOF_PTHREAD_ATTR_T](0)
        self.__align = 0


fn pthread_mutex_lock(mut __mutex: pthread_mutex_t) -> Int32:
    return external_call["pthread_mutex_lock", Int32, UnsafePointer[pthread_mutex_t]](
        UnsafePointer[pthread_mutex_t].address_of(__mutex)
    )


fn pthread_mutex_unlock(mut __mutex: pthread_mutex_t) -> Int32:
    return external_call["pthread_mutex_unlock", Int32, UnsafePointer[pthread_mutex_t]](
        UnsafePointer[pthread_mutex_t].address_of(__mutex)
    )


fn pthread_cond_wait(mut __cond: pthread_cond_t, mut __mutex: pthread_mutex_t) -> Int32:
    return external_call[
        "pthread_cond_wait",
        Int32,
        UnsafePointer[pthread_mutex_t],
        UnsafePointer[pthread_cond_t],
    ](
        UnsafePointer[pthread_mutex_t].address_of(__mutex),
        UnsafePointer[pthread_cond_t].address_of(__cond),
    )


fn pthread_cond_signal(mut __cond: pthread_cond_t) -> Int32:
    return external_call["pthread_cond_signal", Int32, UnsafePointer[pthread_cond_t]](
        UnsafePointer[pthread_cond_t].address_of(__cond),
    )


fn pthread_attr_init(mut __attr: pthread_attr_t) -> Int32:
    return external_call["pthread_attr_init", Int32, UnsafePointer[pthread_attr_t]](
        UnsafePointer[pthread_attr_t].address_of(__attr),
    )


fn pthread_attr_getdetachstate(
    mut __attr: pthread_attr_t, mut __detachstate: Int32
) -> Int32:
    return external_call[
        "pthread_attr_init",
        Int32,
        UnsafePointer[pthread_attr_t],
        UnsafePointer[Int32],
    ](
        UnsafePointer[pthread_attr_t].address_of(__attr),
        UnsafePointer[Int32].address_of(__detachstate),
    )


fn pthread_attr_setdetachstate(
    mut __attr: pthread_attr_t, __detachstate: Int32
) -> Int32:
    return external_call[
        "pthread_attr_init", Int32, UnsafePointer[pthread_attr_t], Int32
    ](UnsafePointer[pthread_attr_t].address_of(__attr), __detachstate)


fn pthread_create[
    T: AnyType
](
    mut __newthread: pthread_t,
    __start_routine: fn (UnsafePointer[T]) -> UInt8,
    __arg: T,
) -> Int32:
    """Create a new thread without attr and arg."""
    return external_call[
        "pthread_create",
        Int32,
        UnsafePointer[pthread_t],
        UInt8,
        fn (UnsafePointer[T]) -> UInt8,
        T,
    ](
        UnsafePointer[pthread_t].address_of(__newthread),
        0,
        __start_routine,
        __arg,
    )


fn pthread_create(
    mut __newthread: pthread_t,
    __start_routine: fn (UnsafePointer[UInt8]) -> UInt8,
) -> Int32:
    """Create a new thread without attr and arg."""
    return external_call[
        "pthread_create",
        Int32,
        UnsafePointer[pthread_t],
        UnsafePointer[UInt8],
        fn (UnsafePointer[UInt8]) -> UInt8,
        UnsafePointer[UInt8],
    ](
        UnsafePointer[pthread_t].address_of(__newthread),
        UnsafePointer[UInt8](),
        __start_routine,
        UnsafePointer[UInt8](),
    )


fn pthread_create(
    mut __newthread: pthread_t,
    __start_routine: fn (UnsafePointer[UInt8]) -> UInt8,
    mut __arg: UnsafePointer[UInt8],
) -> Int32:
    """Create a new thread without attr and arg."""
    return external_call[
        "pthread_create",
        Int32,
        UnsafePointer[pthread_t],
        UnsafePointer[UInt8],
        fn (UnsafePointer[UInt8]) -> UInt8,
        UnsafePointer[UInt8],
    ](
        UnsafePointer[pthread_t].address_of(__newthread),
        UnsafePointer[UInt8](),
        __start_routine,
        __arg,
    )


fn pthread_create(
    mut __newthread: pthread_t,
    mut __attr: pthread_attr_t,
    __start_routine: fn (UnsafePointer[Int]) -> UInt8,
) -> Int32:
    """Create a new thread without attr and arg."""
    return external_call[
        "pthread_create",
        Int32,
        UnsafePointer[pthread_t],
        UnsafePointer[pthread_attr_t],
        fn (UnsafePointer[Int]) -> UInt8,
    ](
        UnsafePointer[pthread_t].address_of(__newthread),
        UnsafePointer[pthread_attr_t].address_of(__attr),
        __start_routine,
    )


fn pthread_create(
    mut __newthread: pthread_t,
    __start_routine: fn () -> UInt8,
) -> Int32:
    """Create a new thread without attr and arg."""
    return external_call[
        "pthread_create",
        Int32,
        UnsafePointer[pthread_t],
        fn () -> UInt8,
    ](
        UnsafePointer[pthread_t].address_of(__newthread),
        __start_routine,
    )


fn pthread_join(__th: pthread_t, mut __thread_return: UInt8) -> Int32:
    return external_call["pthread_join", Int32, pthread_t, UnsafePointer[UInt8]](
        __th,
        UnsafePointer[UInt8].address_of(__thread_return),
    )


fn pthread_join(__th: pthread_t) -> Int32:
    return external_call["pthread_join", Int32, pthread_t, UnsafePointer[UInt8]](
        __th,
        UnsafePointer[UInt8](),
    )


fn pthread_exit(__retval: String) -> UInt8:
    var slen = len(__retval)
    var ptr = UnsafePointer[UInt8]().alloc(slen)

    memcpy(ptr, __retval.unsafe_ptr().bitcast[UInt8](), slen)

    return external_call["pthread_exit", UInt8, UnsafePointer[UInt8]](ptr)


fn pthread_detach(__th: pthread_t) -> Int32:
    return external_call["pthread_detach", Int32, pthread_t](__th)


# ===-------------------------------------------------------------------=== #
# Threading high-level API
# ===-------------------------------------------------------------------=== #

alias ThreadTaskFn = fn (context: UnsafePointer[UInt8]) -> UInt8
alias TaskFn = fn () raises -> None


fn __do_task(context: UnsafePointer[UInt8]) -> UInt8:
    var task = context.bitcast[TaskFn]()
    try:
        task[]()
    except err:
        logger.error("Task failed: " + str(err))
    task.free()
    return 0


fn start_thread(task: TaskFn) raises -> UInt64:
    """Create and start a new thread with the given task function.

    Args:
        task: The function to run in the new thread.

    Returns:
        Thread ID if successful.

    Raises:
        Error if thread creation fails.
    """
    var p = UnsafePointer[TaskFn].alloc(1)
    __get_address_as_uninit_lvalue(p.address) = task
    var context = UnsafePointer[UInt8]()
    context = p.bitcast[UInt8]()
    return start_thread(__do_task, context)


struct ThreadContext[T: AnyType]:
    var task: fn (context: UnsafePointer[T]) raises -> None
    var data: UnsafePointer[T]

    fn __init__(
        out self,
        task: fn (context: UnsafePointer[T]) raises -> None,
        data: UnsafePointer[T],
    ):
        self.task = task
        self.data = data

    fn __call__(mut self) raises:
        self.task(self.data)

    fn free(owned self):
        self.data.free()


fn __do_task_with_context[T: AnyType](context: UnsafePointer[UInt8]) -> UInt8:
    var thread_context = context.bitcast[ThreadContext[T]]()
    try:
        thread_context[]()
    except err:
        logger.error("Task failed: " + str(err))
    thread_context.free()
    return 0


fn start_thread[
    T: AnyType
](
    task: fn (context: UnsafePointer[T]) raises -> None, data: UnsafePointer[T]
) raises -> UInt64:
    """Create and start a new thread with the given task function.

    Args:
        task: The function to run in the new thread.
        data: Pointer to thread context data.

    Returns:
        Thread ID if successful.

    Raises:
        Error if thread creation fails.
    """
    var p = UnsafePointer[ThreadContext[T]].alloc(1)
    __get_address_as_uninit_lvalue(p.address) = ThreadContext[T](task, data)
    var context = UnsafePointer[UInt8]()
    context = p.bitcast[UInt8]()
    return start_thread(__do_task_with_context[T], context)


fn start_thread(task: ThreadTaskFn, mut context: UnsafePointer[UInt8]) raises -> UInt64:
    """Create and start a new thread with the given task function and context.

    Args:
        task: The function to run in the new thread.
        context: Pointer to thread context data.

    Returns:
        Thread ID if successful.

    Raises:
        Error if thread creation fails.
    """
    var thread_id: UInt64 = 0
    if pthread_create(thread_id, task, context) != 0:
        raise Error("Failed to create thread")
    return thread_id

# Shared consumer roster for the separately qualified static and dynamic runs.
# Keep each fixture's project-header contract and optional scratch argument
# beside its name so adding a cancellation regression covers both products.
readonly OWNED_IO_CANCELLATION_PROBES=(
    owned_io_cancellation
    owned_descriptor_cancellation
    owned_socket_cancellation
    owned_sleep_wait_cancellation
    owned_open_lock_cancellation
    owned_semaphore_wait_cancellation
    owned_semaphore_cancellation
    owned_signal_wait_cancellation
    owned_entropy_cancellation
    owned_sysv_message_cancellation
)

owned_io_cancellation_headers() {
    printf '%s\n' errno.h pthread.h stdio.h unistd.h bits/alltypes.h
    case "$1" in
        owned_io_cancellation) printf '%s\n' ucontext.h sys/wait.h sys/uio.h ;;
        owned_descriptor_cancellation) printf '%s\n' sys/uio.h poll.h signal.h sys/select.h sys/epoll.h sys/eventfd.h sys/mman.h ;;
        owned_socket_cancellation) printf '%s\n' sys/socket.h sys/un.h sys/uio.h ;;
        owned_sleep_wait_cancellation) printf '%s\n' time.h threads.h sys/wait.h sys/resource.h ;;
        owned_open_lock_cancellation) printf '%s\n' fcntl.h sys/stat.h sys/mman.h ;;
        owned_semaphore_wait_cancellation) printf '%s\n' semaphore.h ;;
        owned_semaphore_cancellation) printf '%s\n' semaphore.h sys/mman.h ;;
        owned_signal_wait_cancellation) printf '%s\n' signal.h time.h ;;
        owned_entropy_cancellation) printf '%s\n' sys/random.h sys/mman.h ;;
        owned_sysv_message_cancellation) printf '%s\n' sys/msg.h sys/ipc.h sys/wait.h ;;
        *) return 1 ;;
    esac
}

owned_io_cancellation_arguments() {
    if [ "$1" = owned_open_lock_cancellation ]; then printf '%s\n' "$2"; fi
}

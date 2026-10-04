#pragma once

#ifndef MESH_THREAD_SIGNALS_H
#define MESH_THREAD_SIGNALS_H

#include <csignal>
#include <pthread.h>

namespace invilite::Mesh {

    // Block SIGPIPE in the current thread.
    // A ::write() to a pipe whose read end has been closed (e.g. during shutdown races)
    // would otherwise raise SIGPIPE and terminate the whole process. By blocking it only
    // within libmeshlink's threads, the host application's signal handling is unaffected.
    //
    // Intended to be called as the first statement of every thread body we launch
    // (ioLoop, managementLoop, dispatchLoop, handshake workers, probe workers).
    //
    // TODO: consider centralising this via a small "start a Network thread" helper
    // once the probe worker lands — by then we'll have 5+ thread-entry points.
    inline void blockSigpipeInCurrentThread() {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &mask, nullptr);
    }

} // namespace invilite::Mesh

#endif // MESH_THREAD_SIGNALS_H
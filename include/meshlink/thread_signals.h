#pragma once

#ifndef MESH_THREAD_SIGNALS_H
#define MESH_THREAD_SIGNALS_H

#include <csignal>
#include <pthread.h>

namespace invilite::Mesh {

    // Blocks SIGPIPE in the calling thread, so a write to a closed pipe or socket cannot terminate the host process.
    // Done per thread, so the host application's own signal handling is unaffected.
    // Call it first in every thread body the library launches.
    inline void blockSigpipeInCurrentThread() {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &mask, nullptr);
    }

} // namespace invilite::Mesh

#endif // MESH_THREAD_SIGNALS_H
#include "ik/rand.h"

#if defined(__linux__) || defined(__APPLE__)

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "ik/error.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif


int ik_rand(uint8_t*  bytes, uintptr_t size)
{
    int const fd  = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0){
        return IK_ERR_URANDOM;
    }

    for (;;){
        int const l  = (int)(read(fd, bytes, size));
        if (l <    0  ) {
            if (errno == EINTR) {
                continue;
            }

            close(fd);
            return IK_ERR_URANDOM;
        }

        if (l >= size) {
            close(fd);
            return 0;
        }

        size  -= l;
        bytes += l;
    }
    close(fd);
}

#elif defined(ESP_PLATFORM)

#include "esp_system.h"
int ik_rand(uint8_t*  bytes, uintptr_t size)
{
    esp_fill_random(bytes, size);
}
#endif

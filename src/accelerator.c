/* Best-effort Linux accelerator discovery; no driver or SDK is required. */
#include "accelerator.h"
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
static int count_prefix(const char *path, const char *prefix)
{
    DIR *d = opendir(path);
    struct dirent *ent;
    int n = 0;
    if (!d)
        return -1;
    while ((ent = readdir(d)) != NULL) {
        const char *p = ent->d_name;
        size_t l = strlen(prefix);
        if (strncmp(p, prefix, l) != 0 || p[l] < '0' || p[l] > '9')
            continue;
        p += l;
        while (*p >= '0' && *p <= '9')
            p++;
        if (*p == '\0')
            n++;
    }
    closedir(d);
    return n;
}
#endif

void hm_accelerator_report(void)
{
#ifdef __linux__
    int cards = count_prefix("/sys/class/drm", "card");
    int render = count_prefix("/dev/dri", "renderD");
    int nvidia = count_prefix("/dev", "nvidia");
    char card_text[24], render_text[24], nvidia_text[24];
    if (cards < 0) snprintf(card_text, sizeof(card_text), "unknown");
    else snprintf(card_text, sizeof(card_text), "%d", cards);
    if (render < 0) snprintf(render_text, sizeof(render_text), "unknown");
    else snprintf(render_text, sizeof(render_text), "%d", render);
    if (nvidia < 0) snprintf(nvidia_text, sizeof(nvidia_text), "unknown");
    else snprintf(nvidia_text, sizeof(nvidia_text), "%d", nvidia);
    printf("accelerators: DRM cards %s, render nodes %s, NVIDIA device nodes %s, AMD KFD %s\n",
           card_text, render_text, nvidia_text,
           access("/dev/kfd", F_OK) == 0 ? "present" : "not detected");
    printf("accelerator backend: none (device nodes do not establish driver usability)\n");
#else
    printf("accelerators: detection not supported on this platform\n");
    printf("accelerator backend: none\n");
#endif
}

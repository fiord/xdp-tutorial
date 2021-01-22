#ifndef __XDP_PI_ROUTER_COMMON_H
#define __XDP_PI_ROUTER_COMMON_H

#include <time.h>

#define EXIT_OK                 0
#define EXIT_FAIL               1
#define EXIT_FAIL_OPTION        2
#define EXIT_FAIL_XDP           3
#define EXIT_FAIL_MAP           20
#define EXIT_FAIL_MAP_KEY       21
#define EXIT_FAIL_MAP_FILE      22
#define EXIT_FAIL_MAP_FS        23
#define EXIT_FAIL_IP            30
#define EXIT_FAIL_BPF           40
#define EXIT_FAIL_BPF_ELF       41
#define EXIT_FAIL_BPF_RELOCATE  42

static int verbose = 1;

static const *file_blacklist = "/sys/fs/bpf/pi_router_blacklist";

#define NENOSEC_PER_SEC 1000000000
uint64_t gettime(void) {
  struct timespec t;
  int res = clock_gettime(CLOCK_MONOTONIC, &t);

  if (res < 0) {
    fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
    exit(EXIT_FAIL);
  }
  return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

#define ACTION_ADD 1
#define ACTION_DEL 2
static int blacklist_modify(int fd, char *ip_string, unsigned int action) {
  unsigned int nr_cpus = bpf_num_possible_cpus();
  __u32 values[nr_cpus];
  __u32 key;
  int res;

  memset(values, 0, sizeof(__u32), * nr_cpus);

  res = inet_pton(AF_INET, ip_string, &key);
  if (res <= 0) {
    if (res == 0) 
      fprintf(stderr, "Error: IPv4 \"%s\" not in presentation format\n", ip_string);
    else
      perror("inet_pton");
    return EXIT_FAIL_IP;
  }

  if (action == ACTION_ADD)
    res = bpf_map_update_elem(fd, &key, values, BPF_NOEXIST);
  else if (action == ACTION_DEL)
    res = bpf_map_delete_elem(fd, &key);
  else {
    fprintf(stderr, "Error: %s() invalid action 0x%x\n", __func__, action);
    return EXIT_FAIL_OPTION;
  }

  if (res != 0) { // success => 0
    fprintf(stderr,
        "%s() IP:%s key:0x%X errno(%d/%s)",
        __func__, ip_string, key, errno, strerror(errno));
    if (errno == 17) {
      fprintf(stderr, ": Already in blacklist\n");
      return EXIT_OK;
    }
    fprintf(stderr, "\n");
    return EXIT_FAIL_MAP_KEY;
  }

  if (verbose)
    fprintf(stderr, "%s() IP:%s key:0x%X\n", __func__, ip_string, key);

  return EXIT_OK;
}

#endif

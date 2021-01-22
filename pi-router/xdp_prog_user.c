static const char *__doc__="XDP pi-router: cmd-tool";

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>

#include <sys/resource.h>
#include <getopt.h>
#include <time.h>

#include <arpa/inet.h>

// TODO: remove unnecessary import
// #include "../common/xdp_stats_kern_user.h"
// #include "../common/xdp_stats_kern.h"
#include "common.h"

static const struct option long_options[] = {
  {"help",  no_argument,        NULL, 'h'},
  {"add",   no_argument,        NULL, 'a'},
  {"del",   no_argument,        NULL, 'x'},
  {"ip",    required_argument,  NULL, 'i'},
  {"stats", no_argument,        NULL, 's'},
  {"sec",   required_argument,  NULL, 's'},
  {"list",  no_argument,        NULL, 'l'},
  {0, 0, NULL, 0}
};

#define XDP_ACTION_MAX (XDP_TX + 1)
#define XDP_ACTION_MAX_STRLEN 11
static const char *xdp_action_names[XDP_ACTION_MAX] = {
  [XDP_ABORTED] = "XDP_ABORTED",
  [XDP_DROP]    = "XDP_DROP",
  [XDP_PASS]    = "XDP_PASS",
  [XDP_TX]      = "XDP_TX",
};

static void usage(char *argv[]) {
  int i;
  printf("\nDOCUMENTATION:\n%s\n", __doc__);
  printf("\n");
  printf("Usage: %s (options-see-below)\n", argv[0]);
  printf("### Listing options:\n");
  for (i = 0; long_options[i].name != 0; i++) {
    printf("  --%-12s", long_options[i].name);
    if (long_options[i].flag != NULL)
      printf(" flag (internal value: %d)", *long_options[i].flag);
    else
      printf(" short-option: -%c", long_options[i].val);
    printf("\n");
  }
  printf("\n");
}

int open_bpf_map(const char *file) {
  int fd = bpf_obj_get(file);
  if (fd < 0) {
    printf("Error: failed to open bpf map file: %s err(%d): %s\n",
        file, errno, strerror(errno));
    exit(EXIT_FAIL_MAP_FILE);
  }
  return fd;
}

static __u32 get_key32_value32_percpu(int fd, __u32 key) {
  // for percpu maps, userspace gets a value per possible CPU
  unsigned int nr_cpus = bpf_num_possible_cpus();
  __u32 values[nr_cpus];
  __u32 sum = 0;
  int i;

  if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
    fprintf(stderr, "Error: bpf_map_lookup_elem failed key:0x%X\n", key);
    return 0;
  }

  for (i = 0; i < nr_cpus; i++)
    sum += values[i];
  return sum;
}

static void blacklist_print_ipv4(__u32 ip, __u32 count) {
  char ip_txt[INET_ADDRSTRLEN] = {0};
  if (!inet_ntop(AF_INET, &ip, ip_txt, sizeof(ip_txt))) {
    fprintf(stderr, "Error: Cannot convert __u32 IP:0x%X to IP-txt\n", ip);
    exit(EXIT_FAIL_IP);
  }
  printf("\n \"%s\": %llu", ip_txt, count);
}

static void blacklist_list_all_ipv4(int fd) {
  __u32 key, *prev_key = NULL;
  __u32 value;

  while(bpf_map_get_next_key(fd, prev_key, &key) == 0) {
    printf("%s", key ? "," : "");
    value = get_key32_value32_percpu(fd, key);
    blacklist_print_ipv4(key, value);
    prev_key = &key;
  }
  printf("%s", key ? "," : "");
}

int main(int argc, char **argv) {
#define STR_MAX 42
  char _ip_string_buf[STR_MAX] = {};
  char *ip_string = NULL;

  unsigned int action = 0;
  bool stats = false;
  int interval = 1;
  int fd_blacklist;
  int longindex = 0;
  bool do_list = false;
  int opt;
  
  while((opt == getopt_long(argc, argv, "adshi:t:u:",
          long_options, &longindex)) != -1) {
    switch (opt) {
      case 'a':
        action |= ACTION_ADD;
        break;
      case 'x':
        action |= ACTION_DEL;
        break;
      case 'i':
        if (!optarg || strlen(optarg) >= STR_MAX) {
          printf("Error: src ip too long or NULL\n");
          goto fail_opt;
        }
        ip_string = (char*)&_ip_string_buf;
        strncpy(ip_string, optarg, STR_MAX);
        break;
      case 'u':
        break;
      case 's': // --stats && --sec
        stats = true;
        if (optarg)
          interval = atoi(optarg);
        break;
      case 'l':
        do_list = true;
        break;
      case 'h':
      fail_opt:
      default:
        usage(argv);
        return EXIT_FAIL_OPTION;
    }
  }

  // update blacklist
  if (action) {
    int res = 0;

    if (!ip_string) {
      fprintf(stderr, "Error: action require type+data, e.g option --ip\n");
      goto fail_opt;
    }

    fd_blacklist = open_bpf_map(file_blacklist);
    res = blacklist_modify(fd_blacklist, ip_string, action);
    close(fd_blacklist);

    return res;
  }

  if (argv[optind] != NULL) {
    fprintf(stderr, "Error: Unknown non-option argument: %s\n", argv[optind]);
    goto fail_opt;
  }

  if (do_list) {
    printf("{");

    fd_blacklist = open_bpf_map(file_blacklist);
    blacklist_list_all_ipv4(fd_blacklist);
    close(fd_blacklist);
    printf("\n}\n");
  }
  return EXIT_OK;
}

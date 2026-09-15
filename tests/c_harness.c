/*
 * c_harness.c - Cross-platform C89 test harness implementation.
 */

#include "c_harness.h"

int g_tests_run = 0;
int g_tests_failed = 0;
const char *g_current_test_name = "";

static int g_wsa_initialized = 0;

void test_harness_init(void) {
#if defined(_WIN32) || defined(_MSC_VER)
  if (!g_wsa_initialized) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    g_wsa_initialized = 1;
  }
#endif
}

void test_sleep_ms(int ms) {
#if defined(_WIN32) || defined(_MSC_VER)
  Sleep((DWORD)ms);
#else
  usleep((useconds_t)ms * 1000);
#endif
}

static test_uint64_t test_hton64(test_uint64_t val) {
  test_uint32_t hi;
  test_uint32_t lo;
  hi = (test_uint32_t)(val >> 32);
  lo = (test_uint32_t)(val & 0xFFFFFFFFULL);
  return (((test_uint64_t)htonl(lo)) << 32) | htonl(hi);
}

static test_uint64_t test_ntoh64(test_uint64_t val) { return test_hton64(val); }

const char *get_memcached_bin(void) {
  const char *env = getenv("MEMCACHED_BIN");
  if (env && strlen(env) > 0) {
    return env;
  }
#if defined(_WIN32) || defined(_MSC_VER)
  return "memcached.exe";
#else
  return "./memcached";
#endif
}

const char *get_memcached_emulator(void) {
  const char *env = getenv("MEMCACHED_EMULATOR");
  if (env && strlen(env) > 0) {
    return env;
  }
  return NULL;
}

int find_free_port(void) {
  test_socket_t sock;
  struct sockaddr_in sin;
  test_socklen_t len;
  int port = 0;

  test_harness_init();

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == TEST_INVALID_SOCKET) {
    return 11211;
  }

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = 0;

  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == 0) {
    len = sizeof(sin);
    if (getsockname(sock, (struct sockaddr *)&sin, &len) == 0) {
      port = ntohs(sin.sin_port);
    }
  }

#if defined(_WIN32) || defined(_MSC_VER)
  closesocket(sock);
#else
  close(sock);
#endif

  return (port > 0) ? port : 11211;
}

int srv_start(struct memcached_srv *srv, int port, const char *extra_args) {
  const char *bin;
  const char *emu;
  char port_str[16];
  char cmd_buf[1024];

  test_harness_init();

  if (port <= 0) {
    port = find_free_port();
  }

  srv->port = port;
  srv->pid = TEST_INVALID_PID;

  bin = get_memcached_bin();
  emu = get_memcached_emulator();

  strncpy(srv->bin_path, bin, sizeof(srv->bin_path) - 1);
  srv->bin_path[sizeof(srv->bin_path) - 1] = 0;

  if (emu) {
    strncpy(srv->emulator, emu, sizeof(srv->emulator) - 1);
    srv->emulator[sizeof(srv->emulator) - 1] = 0;
  } else {
    srv->emulator[0] = 0;
  }

  sprintf(port_str, "%d", port);

#if defined(_WIN32) || defined(_MSC_VER)
  {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    snprintf(cmd_buf, sizeof(cmd_buf), "%s -l 127.0.0.1 -p %s -U 0 %s", bin,
             port_str, extra_args ? extra_args : "");

    if (!CreateProcessA(NULL, cmd_buf, NULL, NULL, FALSE, 0, NULL, NULL, &si,
                        &pi)) {
      fprintf(stderr, "Failed to start server: %s\n", cmd_buf);
      return -1;
    }
    CloseHandle(pi.hThread);
    srv->pid = pi.hProcess;
  }
#else
  {
    pid_t p;
    p = fork();
    if (p < 0) {
      return -1;
    }
    if (p == 0) {
      char *argv[32];
      int idx = 0;
      char extra_copy[512];
      char *tok;

      if (emu && strlen(emu) > 0) {
        argv[idx++] = (char *)emu;
      }
      argv[idx++] = (char *)bin;
      argv[idx++] = "-l";
      argv[idx++] = "127.0.0.1";
      argv[idx++] = "-p";
      argv[idx++] = port_str;
      argv[idx++] = "-U";
      argv[idx++] = "0";

      if (getuid() == 0 || geteuid() == 0) {
        argv[idx++] = "-u";
        argv[idx++] = "root";
      }

      if (extra_args && strlen(extra_args) > 0) {
        strncpy(extra_copy, extra_args, sizeof(extra_copy) - 1);
        extra_copy[sizeof(extra_copy) - 1] = 0;
        tok = strtok(extra_copy, " ");
        while (tok && idx < 30) {
          argv[idx++] = tok;
          tok = strtok(NULL, " ");
        }
      }
      argv[idx] = NULL;

      if (!getenv("TEST_DEBUG")) {
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
      }

      execvp(argv[0], argv);
      _exit(127);
    }
    srv->pid = p;
  }
#endif

  {
    int attempt;
    for (attempt = 0; attempt < 100; attempt++) {
      struct memcached_client c;
      test_sleep_ms(20);
      if (client_connect(&c, port) == 0) {
        client_close(&c);
        return 0;
      }
    }
  }

  fprintf(stderr, "Server startup timed out on port %d\n", port);
  srv_stop(srv);
  return -1;
}

void srv_stop(struct memcached_srv *srv) {
  if (!srv)
    return;

#if defined(_WIN32) || defined(_MSC_VER)
  if (srv->pid != TEST_INVALID_PID) {
    TerminateProcess(srv->pid, 0);
    WaitForSingleObject(srv->pid, 2000);
    CloseHandle(srv->pid);
    srv->pid = TEST_INVALID_PID;
  }
#else
  if (srv->pid != TEST_INVALID_PID) {
    int status;
    kill(srv->pid, SIGTERM);
    waitpid(srv->pid, &status, 0);
    srv->pid = TEST_INVALID_PID;
  }
#endif
}

int run_cmd_capture(const char *cmd_line, char *out_buf, size_t max_len,
                    int *exit_code) {
  FILE *fp;
  size_t total = 0;

  if (out_buf && max_len > 0) {
    out_buf[0] = 0;
  }

#if defined(_WIN32) || defined(_MSC_VER)
  fp = _popen(cmd_line, "r");
#else
  fp = popen(cmd_line, "r");
#endif

  if (!fp) {
    if (exit_code)
      *exit_code = -1;
    return -1;
  }

  if (out_buf && max_len > 0) {
    char temp[256];
    while (fgets(temp, sizeof(temp), fp)) {
      size_t n = strlen(temp);
      if (total + n < max_len - 1) {
        memcpy(out_buf + total, temp, n);
        total += n;
        out_buf[total] = 0;
      }
    }
  }

#if defined(_WIN32) || defined(_MSC_VER)
  {
    int ret = _pclose(fp);
    if (exit_code)
      *exit_code = ret;
  }
#else
  {
    int status = pclose(fp);
    if (exit_code) {
      if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
      } else {
        *exit_code = -1;
      }
    }
  }
#endif

  return 0;
}

int client_connect(struct memcached_client *c, int port) {
  struct sockaddr_in sin;
  test_socket_t s;

  test_harness_init();

  c->sock = TEST_INVALID_SOCKET;
  c->buf_len = 0;
  c->buf_pos = 0;

  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == TEST_INVALID_SOCKET) {
    return -1;
  }

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr("127.0.0.1");
  sin.sin_port = htons((test_uint16_t)port);

  if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
#if defined(_WIN32) || defined(_MSC_VER)
    closesocket(s);
#else
    close(s);
#endif
    return -1;
  }

  c->sock = s;
  return 0;
}

void client_close(struct memcached_client *c) {
  if (!c || c->sock == TEST_INVALID_SOCKET)
    return;

#if defined(_WIN32) || defined(_MSC_VER)
  closesocket(c->sock);
#else
  close(c->sock);
#endif
  c->sock = TEST_INVALID_SOCKET;
  c->buf_len = 0;
  c->buf_pos = 0;
}

int client_send(struct memcached_client *c, const void *data, size_t len) {
  const char *ptr = (const char *)data;
  size_t remaining = len;

  while (remaining > 0) {
    int n;
#if defined(_WIN32) || defined(_MSC_VER)
    n = send(c->sock, ptr, (int)remaining, 0);
#else
    n = (int)send(c->sock, ptr, remaining, 0);
#endif
    if (n <= 0) {
      return -1;
    }
    remaining -= (size_t)n;
    ptr += n;
  }
  return 0;
}

int client_send_str(struct memcached_client *c, const char *str) {
  return client_send(c, str, strlen(str));
}

int client_read_bytes(struct memcached_client *c, void *buf, size_t count) {
  char *out = (char *)buf;
  size_t needed = count;

  while (needed > 0) {
    if (c->buf_pos < c->buf_len) {
      size_t avail = c->buf_len - c->buf_pos;
      size_t take = (avail < needed) ? avail : needed;
      memcpy(out, c->buf + c->buf_pos, take);
      c->buf_pos += take;
      out += take;
      needed -= take;
    } else {
      int n;
#if defined(_WIN32) || defined(_MSC_VER)
      n = recv(c->sock, c->buf, (int)sizeof(c->buf), 0);
#else
      n = (int)recv(c->sock, c->buf, sizeof(c->buf), 0);
#endif
      if (n <= 0) {
        return -1;
      }
      c->buf_len = (size_t)n;
      c->buf_pos = 0;
    }
  }
  return 0;
}

int client_readline(struct memcached_client *c, char *line_buf,
                    size_t max_len) {
  size_t idx = 0;

  if (!line_buf || max_len == 0)
    return -1;

  while (idx < max_len - 1) {
    char ch;
    if (client_read_bytes(c, &ch, 1) != 0) {
      return -1;
    }
    line_buf[idx++] = ch;
    if (ch == '\n') {
      break;
    }
  }
  line_buf[idx] = '\0';
  return (int)idx;
}

int client_set(struct memcached_client *c, const char *key, const void *val,
               size_t val_len, unsigned int flags, int exptime, char *resp,
               size_t resp_len) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "set %s %u %d %lu\r\n", key, flags, exptime,
           (unsigned long)val_len);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (val_len > 0) {
    if (client_send(c, val, val_len) != 0)
      return -1;
  }
  if (client_send_str(c, "\r\n") != 0)
    return -1;

  if (resp && resp_len > 0) {
    char line[128];
    if (client_readline(c, line, sizeof(line)) < 0)
      return -1;
    {
      size_t l = strlen(line);
      while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n')) {
        line[--l] = '\0';
      }
    }
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_add(struct memcached_client *c, const char *key, const void *val,
               size_t val_len, unsigned int flags, int exptime, char *resp,
               size_t resp_len) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "add %s %u %d %lu\r\n", key, flags, exptime,
           (unsigned long)val_len);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (val_len > 0) {
    if (client_send(c, val, val_len) != 0)
      return -1;
  }
  if (client_send_str(c, "\r\n") != 0)
    return -1;

  if (resp && resp_len > 0) {
    char line[128];
    if (client_readline(c, line, sizeof(line)) < 0)
      return -1;
    {
      size_t l = strlen(line);
      while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
        line[--l] = '\0';
    }
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_replace(struct memcached_client *c, const char *key, const void *val,
                   size_t val_len, unsigned int flags, int exptime, char *resp,
                   size_t resp_len) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "replace %s %u %d %lu\r\n", key, flags, exptime,
           (unsigned long)val_len);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (val_len > 0) {
    if (client_send(c, val, val_len) != 0)
      return -1;
  }
  if (client_send_str(c, "\r\n") != 0)
    return -1;

  if (resp && resp_len > 0) {
    char line[128];
    if (client_readline(c, line, sizeof(line)) < 0)
      return -1;
    {
      size_t l = strlen(line);
      while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
        line[--l] = '\0';
    }
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_append(struct memcached_client *c, const char *key, const void *val,
                  size_t val_len, char *resp, size_t resp_len) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "append %s 0 0 %lu\r\n", key,
           (unsigned long)val_len);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (val_len > 0) {
    if (client_send(c, val, val_len) != 0)
      return -1;
  }
  if (client_send_str(c, "\r\n") != 0)
    return -1;

  if (resp && resp_len > 0) {
    char line[128];
    if (client_readline(c, line, sizeof(line)) < 0)
      return -1;
    {
      size_t l = strlen(line);
      while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
        line[--l] = '\0';
    }
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_prepend(struct memcached_client *c, const char *key, const void *val,
                   size_t val_len, char *resp, size_t resp_len) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "prepend %s 0 0 %lu\r\n", key,
           (unsigned long)val_len);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (val_len > 0) {
    if (client_send(c, val, val_len) != 0)
      return -1;
  }
  if (client_send_str(c, "\r\n") != 0)
    return -1;

  if (resp && resp_len > 0) {
    char line[128];
    if (client_readline(c, line, sizeof(line)) < 0)
      return -1;
    {
      size_t l = strlen(line);
      while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
        line[--l] = '\0';
    }
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_cas(struct memcached_client *c, const char *key, const void *val,
               size_t val_len, test_uint64_t cas_id, unsigned int flags,
               int exptime, char *resp, size_t resp_len) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "cas %s %u %d %lu %llu\r\n", key, flags, exptime,
           (unsigned long)val_len, (unsigned long long)cas_id);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (val_len > 0) {
    if (client_send(c, val, val_len) != 0)
      return -1;
  }
  if (client_send_str(c, "\r\n") != 0)
    return -1;

  if (resp && resp_len > 0) {
    char line[128];
    if (client_readline(c, line, sizeof(line)) < 0)
      return -1;
    {
      size_t l = strlen(line);
      while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
        line[--l] = '\0';
    }
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_get(struct memcached_client *c, const char *key, char *val_out,
               size_t val_max, unsigned int *flags_out) {
  return client_gets(c, key, val_out, val_max, flags_out, NULL);
}

int client_gets(struct memcached_client *c, const char *key, char *val_out,
                size_t val_max, unsigned int *flags_out,
                test_uint64_t *cas_out) {
  char cmd[1024];
  char line[1024];
  int found = 0;

  snprintf(cmd, sizeof(cmd), "gets %s\r\n", key);
  if (client_send_str(c, cmd) != 0)
    return -1;

  while (1) {
    if (client_readline(c, line, sizeof(line)) < 0)
      return -1;
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strncmp(line, "VALUE ", 6) == 0) {
      char rkey[512];
      unsigned int f = 0;
      size_t bytes = 0;
      unsigned long long cas_val = 0;
      char crlf[2];

      if (sscanf(line, "VALUE %511s %u %lu %llu", rkey, &f, &bytes, &cas_val) >=
          3) {
        if (val_out && val_max > 0) {
          size_t to_read = (bytes < val_max - 1) ? bytes : val_max - 1;
          if (client_read_bytes(c, val_out, to_read) != 0)
            return -1;
          val_out[to_read] = 0;
          if (bytes > to_read) {
            size_t rem = bytes - to_read;
            char discard[128];
            while (rem > 0) {
              size_t d = (rem < sizeof(discard)) ? rem : sizeof(discard);
              if (client_read_bytes(c, discard, d) != 0)
                return -1;
              rem -= d;
            }
          }
        } else {
          size_t rem = bytes;
          char discard[128];
          while (rem > 0) {
            size_t d = (rem < sizeof(discard)) ? rem : sizeof(discard);
            if (client_read_bytes(c, discard, d) != 0)
              return -1;
            rem -= d;
          }
        }
        if (client_read_bytes(c, crlf, 2) != 0)
          return -1;
        if (flags_out)
          *flags_out = f;
        if (cas_out)
          *cas_out = (test_uint64_t)cas_val;
        found = 1;
      }
    }
  }

  return found ? 0 : -1;
}

int client_delete(struct memcached_client *c, const char *key, char *resp,
                  size_t resp_len) {
  char cmd[1024];
  char line[128];
  snprintf(cmd, sizeof(cmd), "delete %s\r\n", key);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (client_readline(c, line, sizeof(line)) < 0)
    return -1;
  {
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
      line[--l] = '\0';
  }
  if (resp && resp_len > 0) {
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_incr(struct memcached_client *c, const char *key, unsigned int delta,
                test_uint64_t *new_val, char *err_buf, size_t err_len) {
  char cmd[1024];
  char line[128];
  snprintf(cmd, sizeof(cmd), "incr %s %u\r\n", key, delta);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (client_readline(c, line, sizeof(line)) < 0)
    return -1;
  {
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
      line[--l] = '\0';
  }
  if (isdigit((unsigned char)line[0])) {
    if (new_val) {
#if defined(_MSC_VER)
      *new_val = (test_uint64_t)_strtoui64(line, NULL, 10);
#else
      *new_val = (test_uint64_t)strtoull(line, NULL, 10);
#endif
    }
    return 0;
  } else {
    if (err_buf && err_len > 0) {
      strncpy(err_buf, line, err_len - 1);
      err_buf[err_len - 1] = 0;
    }
    return 1;
  }
}

int client_decr(struct memcached_client *c, const char *key, unsigned int delta,
                test_uint64_t *new_val, char *err_buf, size_t err_len) {
  char cmd[1024];
  char line[128];
  snprintf(cmd, sizeof(cmd), "decr %s %u\r\n", key, delta);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (client_readline(c, line, sizeof(line)) < 0)
    return -1;
  {
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
      line[--l] = '\0';
  }
  if (isdigit((unsigned char)line[0])) {
    if (new_val) {
#if defined(_MSC_VER)
      *new_val = (test_uint64_t)_strtoui64(line, NULL, 10);
#else
      *new_val = (test_uint64_t)strtoull(line, NULL, 10);
#endif
    }
    return 0;
  } else {
    if (err_buf && err_len > 0) {
      strncpy(err_buf, line, err_len - 1);
      err_buf[err_len - 1] = 0;
    }
    return 1;
  }
}

int client_touch(struct memcached_client *c, const char *key, int exptime,
                 char *resp, size_t resp_len) {
  char cmd[1024];
  char line[128];
  snprintf(cmd, sizeof(cmd), "touch %s %d\r\n", key, exptime);
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (client_readline(c, line, sizeof(line)) < 0)
    return -1;
  {
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
      line[--l] = '\0';
  }
  if (resp && resp_len > 0) {
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_flush_all(struct memcached_client *c, int delay, char *resp,
                     size_t resp_len) {
  char cmd[64];
  char line[64];
  if (delay > 0) {
    snprintf(cmd, sizeof(cmd), "flush_all %d\r\n", delay);
  } else {
    snprintf(cmd, sizeof(cmd), "flush_all\r\n");
  }
  if (client_send_str(c, cmd) != 0)
    return -1;
  if (client_readline(c, line, sizeof(line)) < 0)
    return -1;
  {
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
      line[--l] = '\0';
  }
  if (resp && resp_len > 0) {
    strncpy(resp, line, resp_len - 1);
    resp[resp_len - 1] = 0;
  }
  return 0;
}

int client_version(struct memcached_client *c, char *ver_out, size_t max_len) {
  char line[128];
  if (client_send_str(c, "version\r\n") != 0)
    return -1;
  if (client_readline(c, line, sizeof(line)) < 0)
    return -1;
  {
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\r' || line[l - 1] == '\n'))
      line[--l] = '\0';
  }
  if (strncmp(line, "VERSION ", 8) == 0) {
    if (ver_out && max_len > 0) {
      strncpy(ver_out, line + 8, max_len - 1);
      ver_out[max_len - 1] = 0;
    }
    return 0;
  }
  return -1;
}

int bin_send(struct memcached_client *c, test_uint8_t opcode, const void *key,
             size_t key_len, const void *val, size_t val_len,
             const void *extras, size_t ext_len, test_uint8_t datatype,
             test_uint32_t opaque, test_uint64_t cas) {
  char header[24];
  test_uint32_t total_body;

  total_body = (test_uint32_t)(key_len + val_len + ext_len);

  header[0] = (char)0x80;
  header[1] = (char)opcode;
  *(test_uint16_t *)(header + 2) = htons((test_uint16_t)key_len);
  header[4] = (char)ext_len;
  header[5] = (char)datatype;
  *(test_uint16_t *)(header + 6) = 0;
  *(test_uint32_t *)(header + 8) = htonl(total_body);
  *(test_uint32_t *)(header + 12) = htonl(opaque);
  *(test_uint64_t *)(header + 16) = test_hton64(cas);

  if (client_send(c, header, 24) != 0)
    return -1;
  if (ext_len > 0 && extras) {
    if (client_send(c, extras, ext_len) != 0)
      return -1;
  }
  if (key_len > 0 && key) {
    if (client_send(c, key, key_len) != 0)
      return -1;
  }
  if (val_len > 0 && val) {
    if (client_send(c, val, val_len) != 0)
      return -1;
  }

  return 0;
}

int bin_recv(struct memcached_client *c, struct bin_response *res) {
  char header[24];
  test_uint32_t bodylen;
  size_t val_len;

  if (!res)
    return -1;
  memset(res, 0, sizeof(*res));

  if (client_read_bytes(c, header, 24) != 0)
    return -1;

  res->magic = (test_uint8_t)header[0];
  res->opcode = (test_uint8_t)header[1];
  res->keylen = ntohs(*(test_uint16_t *)(header + 2));
  res->extlen = (test_uint8_t)header[4];
  res->datatype = (test_uint8_t)header[5];
  res->status = ntohs(*(test_uint16_t *)(header + 6));
  res->bodylen = ntohl(*(test_uint32_t *)(header + 8));
  res->opaque = ntohl(*(test_uint32_t *)(header + 12));
  res->cas = test_ntoh64(*(test_uint64_t *)(header + 16));

  bodylen = res->bodylen;

  if (res->extlen > 0) {
    size_t to_read = (res->extlen < sizeof(res->extras) - 1)
                         ? res->extlen
                         : sizeof(res->extras) - 1;
    if (client_read_bytes(c, res->extras, to_read) != 0)
      return -1;
    res->extras[to_read] = 0;
    bodylen -= res->extlen;
  }

  if (res->keylen > 0) {
    size_t to_read = (res->keylen < sizeof(res->key) - 1)
                         ? res->keylen
                         : sizeof(res->key) - 1;
    if (client_read_bytes(c, res->key, to_read) != 0)
      return -1;
    res->key[to_read] = 0;
    bodylen -= res->keylen;
  }

  val_len = (size_t)bodylen;
  if (val_len > 0) {
    size_t to_read =
        (val_len < sizeof(res->val) - 1) ? val_len : sizeof(res->val) - 1;
    if (client_read_bytes(c, res->val, to_read) != 0)
      return -1;
    res->val[to_read] = 0;
    if (val_len > to_read) {
      size_t rem = val_len - to_read;
      char discard[128];
      while (rem > 0) {
        size_t d = (rem < sizeof(discard)) ? rem : sizeof(discard);
        if (client_read_bytes(c, discard, d) != 0)
          return -1;
        rem -= d;
      }
    }
  }

  return 0;
}

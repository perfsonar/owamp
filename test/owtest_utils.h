FILE *tmpSessionDataFile(const char *hex);
OWPContext tmpContext(char **argv);

struct _server_params {
    char *socket_path;
    int (*client_proc)(int, void*);
    void *test_context;
};

void *server_proc(void *context);


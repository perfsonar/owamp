/*
 *        File:         owtest_utils.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  declarations for shared test methods/structs
 */
FILE *tmpSessionDataFile(const char *hex);
OWPContext tmpContext(char **argv);

struct _server_params {
    char *socket_path;
    int (*client_proc)(int, void*);
    void *test_context;
};

void *run_server(struct _server_params *);

 


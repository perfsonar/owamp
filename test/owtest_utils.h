/*
 *        File:         owtest_utils.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  declarations for shared test methods/structs
 */

#define TMPNAME_FMT "owtest.XXXXXX"

FILE *tmpFile(void);
FILE *tmpSessionDataFile(const char *hex);
void rmdir_recursive(const char *dir_name);

OWPContext tmpContext(char **argv);

struct _server_params {
    char *socket_path;
    int (*client_proc)(int, void*);
    void *test_context;
};

void *run_server(struct _server_params *);

int count_occurrences(const char *haystack, const char *needle);
 


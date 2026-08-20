/*
 *        File:         owtest_utils.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  declarations for shared test methods/structs
 */

#ifdef P_tmpdir
#define TMPNAME_FMT (P_tmpdir "/owtest.XXXXXX")
#else
#define TMPNAME_FMT "/tmp/owtest.XXXXXX"
#endif



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
 


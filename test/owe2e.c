/*
 *        File:         owe2e.c
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Sanity run of owping & owampd
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

#include <owamp/owamp.h>
#include <owamp/owampP.h>
#include <I2util/util.h>
#include <I2util/addr.h>

#include "./owtest_utils.h"


/*
 * Function:        find_available_port 
 *
 * Description:     find a port number that can be bound to
 *
 * In Args:         minimum and maximum ports to use for searching 
 *
 * Out Args:
 *
 * Scope:
 * Returns:         available port number
 * Side Effect:     exit(1) in case of error or not found
 */
uint16_t find_available_port(uint16_t first_port, uint16_t last_port) {

    for(uint16_t port=first_port; port <= last_port; port++) {
        
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            printf("error: failed to create socket!\n");
            exit(1);
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        int res = bind(s, (struct sockaddr *) &addr, sizeof addr);
        if (res < 0) {
            if (errno != EADDRINUSE) {
                perror("unexpected bind error");
            }
        }
        close(s);
        if (res >= 0) {
            return port;
        }
    }
    printf("error: failed to find an available port\n");
    exit(1);
}

/*
 * Function:        launch_owampd
 *
 * Description:     launch owampd and listen on localhost:port
 *
 * In Args:         owampd control port
 *
 * Out Args:        created temporary directory for config files
 *                  pid of owping process
 *
 * Scope:
 * Returns:         non-zero in case of error
 * Side Effect:     an owampd process is started and tmp directory
 *                  is created that should be deleted
 */
int launch_owampd(uint16_t port, char *config_dir, size_t config_dir_size, pid_t *child_pid) {

    if (config_dir_size <= strlen(TMPNAME_FMT)) {
        fprintf(stderr, "config dir buffer too small, need %lu bytes\n", strlen(TMPNAME_FMT) + 1);
        return 1;
    }

    strcpy(config_dir, TMPNAME_FMT);
    if(!mkdtemp(config_dir)) {
        perror("mkdtemp error");
        return 1; 
    }

    char filename[PATH_MAX];
    sprintf(filename, "%s/%s", config_dir, "owamp-server.conf");
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen error");
        return 1;
    } 
    fprintf(f, "srcnode localhost:%d\n", port);
    fclose(f);


    sprintf(filename, "%s/%s", config_dir, "owampd.limits");
    f = fopen(filename, "w");
    if (!f) {
        perror("fopen error");
        return 1;
    }
    fprintf(f, "limit root with disk=0, bandwidth=0, delete_on_fetch=on\n");
    fprintf(f, "limit regular with parent=root, disk=10G, bandwidth=20M\n");
    fprintf(f, "assign default regular\n");
    fclose(f);

    if((*child_pid = fork()) < 0) {
        perror("fork error");
        return 1;
    }

    if (*child_pid == 0) {
        // this is the child process
        char *argv[] = {
            "../owampd/owampd",
            "-c", config_dir,
            "-R", config_dir,
            "-v",
            "-Z",
            NULL,
        };
        if (execvp(*argv, argv) < 0) {
            perror("execvp error launching owampd");
            exit(1);
        }
    }

    return 0;
}

/*
 * Function:        launch_owping 
 *
 * Description:     launch owping and point it at localhost:port
 *
 * In Args:         owampd control port
 *
 * Out Args:        pid of owping process
 *
 * Scope:
 * Returns:         non-zero in case of error
 * Side Effect:     an owping process is started
 */
int launch_owping(uint16_t port, pid_t *child_pid) {
    
    if ((*child_pid = fork()) < 0) {
        perror("fork error");
        return 1;
    }

    if (*child_pid == 0) {
        // this is the child process

        char address[20];
        sprintf(address, "localhost:%d", port);
    
        char *argv[] = {
            "../owping/owping",
            "-c", "10",
            address,
            NULL,
        };
        if (execvp(*argv, argv) < 0) {
            perror("execvp error launching owping");
            exit(1);
        }
    }

    return 0;
}



/*
 * Function:        main
 *
 * Description:     launch a simulated owamp server & send commands
 *                  so they can be validated in do_server (above)
 *
 * In Args:         argc, argv (unused)
 *
 * Out Args:
 *
 * Scope:           unit test (run using make check)
 * Returns:         non-zero in case of error
 * Side Effect:
 */
int
main(
    int argc __attribute__((unused)),
    char    **argv
) {

    uint16_t port = find_available_port(1024, 0xffff);
    printf("found available port: %d, 0x%04x\n", port, port);

    int exit_code = 1;
    char config_dir_name[PATH_MAX] = {0};
    pid_t server_pid = -1, ping_pid = -1;

    if(launch_owampd(port, config_dir_name, sizeof config_dir_name, &server_pid)) {
        goto cleanup;
    }

    sleep(3); // give server time to startup

    if(launch_owping(port, &ping_pid)) {
        goto cleanup;
    }

    int status; 
    if (waitpid(ping_pid, &status, 0) < 0) {
        perror("waitpid failed waiting for ping proc");
        goto cleanup;
    } else {
        ping_pid = -1; // i.e. don't kill below
    }

    exit_code = 0; // succeeded

cleanup:

    if (ping_pid > 0) {
        kill(ping_pid, SIGKILL);
        waitpid(ping_pid, &status, 0);
    }
    if (server_pid > 0) {
        kill(server_pid, SIGKILL);
        waitpid(server_pid, &status, 0);
    }

    rmdir_recursive(config_dir_name);

    return exit_code;
}


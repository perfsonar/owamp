#include <owamp/owamp.h>
#include <I2util/util.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

//#define SESSION_DATA_FILENAME "./owping-data.session"

//#define SESSION_DATA_FILENAME "/vagrant/owping-data.session"

#define SESSION_DATA \
    "4f7741000000000300000001000000010000000000000001000000000000" \
    "00b800000000000000b8010400010000000100000001263223a27f000001" \
    "0000000000000000000000007f0000010000000000000000000000007f00" \
    "0001dd105eb7304997895d7acd3a00000000dd105eb844c4036100000002" \
    "0a31e7da0000000000000000000000000000000000000000000000000000" \
    "0000000000000000000000000000199999a0000000000000000000000000" \
    "000000000000000091ff91ffdd105eb8642ab6dadd105eb8642f905dff"

#define TMPNAME_FMT "owtest.XXXXXX"

FILE *tmpSessionDataFile(const char *hex) {

    char *filename = (char *) malloc(sizeof TMPNAME_FMT);
    size_t nbytes = strlen(hex)/2;
    uint8_t *bytes = (uint8_t *) malloc(nbytes);
    FILE *fp = NULL;

    strcpy(filename, TMPNAME_FMT);
    int fd = mkstemp(filename);
    if (fd < 0) {
        printf("mkstemp error: %s", strerror(errno));
        goto tmp_file_error;
    }

    fp = fdopen(fd, "w+b");
    if (!fp) {
        printf("fdopen error: %s", strerror(errno));
        goto tmp_file_error;
    }

    if(unlink(filename)) {
        printf("unlink error: %s", strerror(errno));
        goto tmp_file_error;
    }

    if(!I2HexDecode(hex, bytes, nbytes)) {
        printf("I2HexDecode error\n");
        goto tmp_file_error;
    }

    if(fwrite(bytes, 1, nbytes, fp) != nbytes) {
        printf("error writing test data\n");
        goto tmp_file_error;
    }

    rewind(fp);
    free(bytes);
    free(filename);
    return fp;

tmp_file_error:
    if (fp) {
        fclose(fp);
    }
    free(bytes);
    free(filename);
    exit(1);
}



// warning: I2ErrLogImmediate is static, effectively global
OWPContext tmpContext(char **argv) {
    char *progname;
    progname = (progname = strrchr(argv[0], '/')) ? progname+1 : *argv;

    static I2LogImmediateAttr ia;
    ia.line_info = I2NAME | I2MSG | I2LINE | I2FILE;
    ia.fp = stderr;
    I2ErrHandle eh = I2ErrOpen(progname, I2ErrLogImmediate, &ia, NULL, NULL);
    if (!eh) {
        printf("I2ErrOpen failed\n");
        exit(1);
    }

    OWPContext ctx = OWPContextCreate(eh);
    if(!ctx) {
        printf("OWPContextCreate returned NULL\n");
        exit(1);
    }
    return ctx;
}


int
main(
        int     argc    __attribute__((unused)),
        char    **argv
    ) {


    OWPContext ctx = tmpContext(argv);
    OWPSessionHeaderRec hdr;

    OWPError(ctx,OWPErrFATAL,OWPErrINVALID, 
            "test ...123");

    FILE *fp = tmpSessionDataFile(SESSION_DATA);

    int num_rec = OWPReadDataHeader(ctx,fp,&hdr);

    fclose(fp);
    OWPContextFree(ctx);

    if (!num_rec) {
        printf("no header records found\n");
        exit(1);
    }

    if (!hdr.header) {
        printf("header data not initialized\n");
        exit(1);
    }
}


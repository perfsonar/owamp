/*
 *        File:         e2e_utils.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  end-to-end process utililities
 */

typedef int(*output_verification_handler)(const char *);

int verify_owping_output(const char *output);
int verify_twping_output(const char *output);

typedef enum _protocol {OWAMP, TWAMP} PROTOCOL;
int e2e_test(PROTOCOL protocol, const char *authmode, output_verification_handler);

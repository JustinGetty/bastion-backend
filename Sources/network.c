#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <time.h>

#define PORT 8443

/*
Notes:
Compile - gcc Sources/network.c -o networktemp -I/usr/local/include -L/usr/local/lib -lmicrohttpd

*/

static int verify_client_cert(void *cls, struct MHD_Connection *connection,
                              const char *cert, size_t cert_size)
{
    int ret;
    gnutls_x509_crt_t client_cert;
    gnutls_datum_t cert_datum;
    time_t now, activation_time, expiration_time;
    char common_name[256];
    size_t common_name_size = sizeof(common_name);

    if (!cert || cert_size == 0) {
        fprintf(stderr, "❌ No client certificate provided. Rejecting connection.\n");
        return MHD_NO;
    }

    ret = gnutls_x509_crt_init(&client_cert);
    if (ret < 0) {
        fprintf(stderr, "❌ Error initializing certificate object: %s\n", gnutls_strerror(ret));
        return MHD_NO;
    }

    cert_datum.data = (unsigned char *)cert;
    cert_datum.size = cert_size;

    ret = gnutls_x509_crt_import(client_cert, &cert_datum, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        fprintf(stderr, "❌ Error importing client certificate: %s\n", gnutls_strerror(ret));
        gnutls_x509_crt_deinit(client_cert);
        return MHD_NO;
    }

    now = time(NULL);
    activation_time = gnutls_x509_crt_get_activation_time(client_cert);
    expiration_time = gnutls_x509_crt_get_expiration_time(client_cert);

    if (activation_time == (time_t)-1 || expiration_time == (time_t)-1) {
        fprintf(stderr, "❌ Certificate has invalid activation/expiration times.\n");
        gnutls_x509_crt_deinit(client_cert);
        return MHD_NO;
    }

    if (now < activation_time) {
        fprintf(stderr, "❌ Certificate not yet valid (activation time: %ld, now: %ld).\n",
                (long)activation_time, (long)now);
        gnutls_x509_crt_deinit(client_cert);
        return MHD_NO;
    }

    if (now > expiration_time) {
        fprintf(stderr, "❌ Certificate expired (expiration time: %ld, now: %ld).\n",
                (long)expiration_time, (long)now);
        gnutls_x509_crt_deinit(client_cert);
        return MHD_NO;
    }

	//get CN
    ret = gnutls_x509_crt_get_dn_by_oid(client_cert, GNUTLS_OID_X520_COMMON_NAME,
                                         0, 0, common_name, &common_name_size);
    if (ret < 0) {
        fprintf(stderr, "❌ Error retrieving common name from certificate.\n");
		//could reject CN here
        gnutls_x509_crt_deinit(client_cert);
        return MHD_NO;
    }
    printf("✅ Client certificate common name: %s\n", common_name);

	//verify issuer here too

    gnutls_x509_crt_deinit(client_cert);
    return MHD_YES;
}


enum MHD_Result answer_to_connection (void *cls, struct MHD_Connection *connection,
						  const char *url,
						  const char *method, const char *version,
						  const char *upload_data,
						  size_t *upload_data_size, void **con_cls)
{
	printf("URL: %s, METHOD: %s, VERSION: %s\n", url, method, version);
	const char *json_response = "{ \"message\": \"Secure API\", \"status\": 200 }\n";	
	struct MHD_Response *response;
	enum MHD_Result ret;

	response = MHD_create_response_from_buffer(strlen(json_response), (void*)json_response, MHD_RESPMEM_PERSISTENT);

	MHD_add_response_header(response, "Content-Type", "application/json");
	MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
	MHD_add_response_header(response, "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
	MHD_add_response_header(response, "X-Content-Type-Options", "nosniff");
	MHD_add_response_header(response, "X-Frame-Options", "DENY");
	MHD_add_response_header(response, "Referrer-Policy", "no-referrer");

	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	return ret;
}


int main()
{
	struct MHD_Daemon *daemon;
	char *cert_pem_path = "/infinite/Projects/NoPass/Server/certs/server-cert.pem";
	char *key_pem_path = "/infinite/Projects/NoPass/Server/certs/server-key.pem";
	char *ca_bundle_path = "/etc/ssl/certs/ca-certificates.crt";

	FILE *ca_bundle_fp = fopen(ca_bundle_path, "r");
    if (!ca_bundle_fp) {
        perror("Error opening CA bundle file");
        return 1;
    }
    fseek(ca_bundle_fp, 0, SEEK_END);
    long ca_bundle_size = ftell(ca_bundle_fp);
    rewind(ca_bundle_fp);
    char *ca_bundle_crt = (char *)malloc(ca_bundle_size + 1);
    if (!ca_bundle_crt) {
        perror("Error allocating memory for CA bundle");
        fclose(ca_bundle_fp);
        return 1;
    }
    fread(ca_bundle_crt, 1, ca_bundle_size, ca_bundle_fp);
    ca_bundle_crt[ca_bundle_size] = '\0';
    fclose(ca_bundle_fp);

	FILE *cert_file = fopen(cert_pem_path, "r");
	fseek(cert_file, 0, SEEK_END);
	long cert_size = ftell(cert_file);
	rewind(cert_file);
	char *cert_pem = (char *)malloc(cert_size + 1);
	fread(cert_pem, 1, cert_size, cert_file);
	cert_pem[cert_size] = '\0';
	fclose(cert_file);

	FILE *key_file = fopen(key_pem_path, "r");
	fseek(key_file, 0, SEEK_END);
	long key_size = ftell(key_file);
	rewind(key_file);
	char *key_pem = (char *)malloc(key_size + 1);
	fread(key_pem, 1, key_size, key_file);
	key_pem[key_size] = '\0';
	fclose(key_file);

	//implement later: mlock(key_pem, key_size);
	
	

	daemon = MHD_start_daemon(MHD_USE_TLS | MHD_USE_INTERNAL_POLLING_THREAD,
                          PORT, NULL, NULL,
                          &answer_to_connection, NULL,
                          MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                          MHD_OPTION_HTTPS_MEM_KEY, key_pem,
						  MHD_OPTION_CONNECTION_LIMIT, 100,
						  MHD_OPTION_CONNECTION_TIMEOUT, 10,
						  MHD_OPTION_HTTPS_PRIORITIES, "SECURE256:+SECURE128",
						  MHD_OPTION_HTTPS_MEM_TRUST, ca_bundle_crt,
						  //MHD_OPTION_HTTPS_CERT_CALLBACK, verify_client_cert, fix callback
                          MHD_OPTION_END);

	if (MHD_USE_TLS) {
		printf("TLS is ENABLED in MHD_start_daemon\n");
	} else {
		printf("TLS is NOT enabled in MHD_start_daemon\n");
	}

	if (!daemon) {
    perror("MHD_start_daemon failed");
    return 1;
	}


	if (daemon == NULL) return 1;

	getchar();
	free(cert_pem);
	memset(key_pem, 0, key_size);
	free(key_pem);
	MHD_stop_daemon(daemon);
	return 0;
}

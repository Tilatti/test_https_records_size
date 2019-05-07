#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <getopt.h>
#include <stdbool.h>

#include <tls.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MIN(A, B) ((A) > (B) ? (B) : (A))
#define HEADER_STR_SIZE 128
#define HEADER_MAX_LINE_SIZE 128
#define HEADER_MAX_SIZE 1024

/* Print-out on standard output the received HTTP/1.1 response */
int print_received_chunked_response(BIO* bio)
{
  int ret;

  char line[HEADER_MAX_LINE_SIZE];

  char* end_pointer;
  char field_name[HEADER_STR_SIZE];
  char field_value[HEADER_STR_SIZE];
  int n;

  bool is_chunked;
  unsigned int content_length;

#define BUFFER_SIZE HEADER_MAX_SIZE
  char buffer[BUFFER_SIZE];
  unsigned int size_to_read;
  unsigned int read_size;
  unsigned int offset;

  is_chunked = false;
  content_length = 0;

  /* Get the first line of the HTTP header */
  ret = BIO_gets(bio, line, HEADER_MAX_LINE_SIZE);
  if (ret <= 0)
    return -1;
  line[HEADER_MAX_LINE_SIZE - 1] = '\0';

  /* Parse the HTTP header */
  while (line[0] != '\r') { /* Continue to parse until an empty line is detected */
    /* Print-out the line */
    fprintf(stdout, "%s", line);

    /* Parse the HTTP header line to get the Content-Length or the Content-Encoding */
    n = sscanf(line, "%s %s", field_name, field_value);
    if (n == 2) {
      if (strcmp(field_name, "Transfer-Encoding:") == 0) {
        if (strcmp(field_value, "chunked") != 0) {
          fprintf(stdout, "Unknown transfer encoding\n");
          return -1;
        }
        is_chunked = true;
        content_length = 0;
      } else if (strcmp(field_name, "Content-Length:") == 0) {
        is_chunked = false;
        content_length = strtoul(field_value, &end_pointer, 10);
        if (end_pointer[0] != '\0') {
          fprintf(stdout, "Incorrect Content-Length field value\n");
          return -1;
        }
      }
    }

    /* Get the next line of the HTTP header */
    ret = BIO_gets(bio, line, HEADER_MAX_LINE_SIZE);
    if (ret <= 0)
      return -1;
    line[HEADER_MAX_LINE_SIZE - 1] = '\0';
  }

  /* Read the HTTP body */
  if (is_chunked) {
    /* TODO: this implementation fails in the case where there is last chunk marker ("0\r\n\r\n") inside the data payload ... */
    while (((ret = BIO_gets(bio, line, HEADER_MAX_LINE_SIZE)) > 0) && (strncmp(line, "0\r\n", 3) != 0)) {
      read_size = (unsigned int)(ret);

      /* Print-out the content */
      line[read_size] = '\0';
      fprintf(stdout, "%s", line);
    }
    /* Get the last \r\n" */
    ret = BIO_gets(bio, line, HEADER_MAX_LINE_SIZE);
    if (ret <= 0)
      return -1;
  } else if (content_length > 0) {
    size_to_read = MIN(BUFFER_SIZE, content_length);
    while ((size_to_read > 0) && ((ret = BIO_read(bio, buffer, size_to_read)) > 0)) {
      read_size = (unsigned int)(ret);

      /* Compute the remaining size to read */
      offset += read_size;
      size_to_read = MIN(BUFFER_SIZE, content_length - offset);

      /* Print-out the content */
      buffer[read_size] = '\0';
      fprintf(stdout, "%s", buffer);
    }
  }

  return 0;
}

/* Send a request without any body and wait an response */
int get_resource(BIO* bio, const char* request)
{
  int ret;
  size_t size;
  char request_line[HEADER_STR_SIZE];
  uint8_t* buffer;

  snprintf(request_line, HEADER_STR_SIZE, "%s HTTP/1.1\r\n", request);

  /* Send the HTTP request header */
  BIO_puts(bio, request_line);
  BIO_puts(bio, "Host: webserver\r\n");
  BIO_puts(bio, "Connection: keep-alive\r\n");
  BIO_puts(bio, "\r\n");
  BIO_flush(bio);

  /* Receive the HTTP response */
  print_received_chunked_response(bio);

  return ret;
}

/* Get the size of file. */
int get_content_length(FILE* stream, unsigned int* content_length)
{
  int ret;

  ret = fseek(stream, 0, SEEK_END);
  if (ret != 0) {
    fprintf(stderr, "fseek: failed with %i\n", ret);
    fprintf(stderr, "Try with chunked encoding (option -c<chunk size>)");
    return -1;
  }
  ret = ftell(stream);
  if (ret < 0) {
    fprintf(stderr, "ftell: failed with %i\n", ret);
    fprintf(stderr, "Try with chunked encoding (option -c<chunk size>)");
    return -1;
  }
  rewind(stream);
  *content_length = (unsigned int)(ret);

  return 0;
}

/* Send data over an HTTPS connection. 
 * The input data shall come from a regular file, as the input size shall be computable (fseek, ftell syscalls are used).
 * Use the send_chunked_data() to send arbitrary data. */
int send_data(BIO* bio, const char* request, FILE* stream, size_t record_size)
{
  int ret;
  size_t size;

  unsigned int content_length;
  char content_length_line[HEADER_STR_SIZE];
  char request_line[HEADER_STR_SIZE];

  uint8_t* buffer;

  /* Get the stream size */
  ret = get_content_length(stream, &content_length);
  if (ret != 0)
    return ret;

  /* Send the HTTP request header */
  snprintf(request_line, HEADER_STR_SIZE, "%s HTTP/1.1\r\n", request);
  BIO_puts(bio, request_line);
  BIO_puts(bio, "Host: webserver\r\n");
  snprintf(content_length_line, HEADER_STR_SIZE, "Content-Length: %d\r\n", content_length);
  BIO_puts(bio, content_length_line);
  BIO_puts(bio, "Connection: keep-alive\r\n");
  BIO_puts(bio, "Content-Type: application/octet-stream\r\n");
  BIO_puts(bio, "\r\n");
  BIO_flush(bio);

  buffer = malloc(record_size);
  if (buffer == NULL)
    return -1;

  /* Send the file content */
  while ((size = fread(buffer, sizeof(uint8_t), record_size, stream)) != 0) {
    BIO_write(bio, buffer, size);
    BIO_flush(bio);
  }

  /* Receive the HTTP response */
  print_received_chunked_response(bio);
  
  free(buffer);
  return ret;
}

#define CHUNK_HEADER_SIZE 7
#define CHUNK_FOOTER_SIZE 2

/* Send data over an HTTPS connection, using the HTTP/1.1 chunk encoding. */
int send_chunked_data
  (BIO* bio, const char* request, FILE* stream, size_t max_record_size, size_t max_chunk_size, bool send_file_length)
{
  int ret;

  size_t size;
  size_t chunk_size;
  unsigned int record_size;
  unsigned int record_offset;
  unsigned int chunk_offset;
  size_t read_size;

  unsigned int content_length;
  char content_length_line[HEADER_STR_SIZE];
  char request_line[HEADER_STR_SIZE];
  char chunk_header[CHUNK_HEADER_SIZE + 1];

  uint8_t* record_buffer;
  uint8_t* chunk_buffer;
  unsigned int chunk_header_size;
  uint8_t* chunk_buffer_begin;

  /* Send the HTTP request header */
  snprintf(request_line, HEADER_STR_SIZE, "%s HTTP/1.1\r\n", request);
  BIO_puts(bio, request_line);
  BIO_puts(bio, "Host: webserver\r\n");
  BIO_puts(bio, "Connection: keep-alive\r\n");
  BIO_puts(bio, "Content-Type: application/octet-stream\r\n");
  if (send_file_length) {
    /* Get the stream size */
    ret = get_content_length(stream, &content_length);
    if (ret != 0)
      return ret;
    /* Send the Content-Length field */
    snprintf(content_length_line, HEADER_STR_SIZE, "Content-Length: %d\r\n", content_length);
    BIO_puts(bio, content_length_line);
  }
  BIO_puts(bio, "Transfer-Encoding: chunked\r\n");
  BIO_puts(bio, "\r\n");
  BIO_flush(bio);

  record_buffer = malloc(max_record_size);
  if (record_buffer == NULL)
    return -1;
  chunk_buffer = malloc(max_chunk_size);
  if (chunk_buffer == NULL)
    return -1;

  enum {
    READ_CHUNK,
    COPY_CHUNK_TO_RECORD,
    WRITE_RECORD,
    END,
  } state;

  read_size = 0;
  chunk_size = 0;
  record_offset = 0;
  record_size = 0;
  chunk_offset = 0;
  state = READ_CHUNK;

  do {
    switch (state) {
      case READ_CHUNK:
        if (feof(stream) || ferror(stream)) {
          /* No payload, will generate last chunk with a size of zero */
          read_size = 0;
        } else {
          /* Read the payload and copy it */
          read_size = fread(&(chunk_buffer[CHUNK_HEADER_SIZE]), sizeof(uint8_t),
            max_chunk_size - CHUNK_HEADER_SIZE - CHUNK_FOOTER_SIZE, stream);
        }

        /* Compute the chunk header */
        snprintf(chunk_header, CHUNK_HEADER_SIZE, "%X\r\n", (unsigned int)(read_size));
        chunk_header_size = strnlen(chunk_header, CHUNK_HEADER_SIZE);

        /* Compute the buffer begin */
        chunk_buffer_begin = &(chunk_buffer[CHUNK_HEADER_SIZE - chunk_header_size]);

        /* Copy the chunk header and chunk footer */
        memcpy(chunk_buffer_begin, chunk_header, chunk_header_size);
        memcpy(chunk_buffer_begin + chunk_header_size + read_size, "\r\n", CHUNK_FOOTER_SIZE);

        /* Compute the total chunk size */
        chunk_size = chunk_header_size + read_size + CHUNK_FOOTER_SIZE;
        chunk_offset = 0;

        fprintf(stderr, "Read chunk (size: %u)\n", chunk_size);
        break;

      case COPY_CHUNK_TO_RECORD:
        /* Copy the chunk in the record */
        size = MIN(chunk_size - chunk_offset, max_record_size - record_offset);
        memcpy(&(record_buffer[record_offset]), &(chunk_buffer_begin[chunk_offset]), size);
        record_offset += size;
        chunk_offset += size;

        fprintf(stderr, "Copy chunk to record\n");
        break;

      case WRITE_RECORD:
        /* Send a record */
        record_size = record_offset;
        record_offset = 0;
        BIO_write(bio, record_buffer, record_size);
        BIO_flush(bio);

        fprintf(stderr, "Write record (size: %u)\n", record_size);
        break;

      default:
        assert(0);
        break;
    }

    if (read_size == 0) { /* End of file special case: the last chunk (of size null) cannot be bigger than a record */
      if (state == READ_CHUNK)
        state = COPY_CHUNK_TO_RECORD;
      else if (state == COPY_CHUNK_TO_RECORD)
        state = WRITE_RECORD;
      else if (state == WRITE_RECORD)
        state = END;
    } else if ((max_record_size - record_offset) == 0) { /* A record is ready to be transmitted */
      state = WRITE_RECORD;
    } else if ((chunk_size - chunk_offset) == 0) { /* A new chunk is needed */
      state = READ_CHUNK;
    } else { /* A new record is needed */
      state = COPY_CHUNK_TO_RECORD;
    }
  } while (state != END);

  /* Receive the HTTP response */
  print_received_chunked_response(bio);

  free(record_buffer);
  free(chunk_buffer);
  return ret;
}

void print_usage(const char* prog)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s --send [-l] [-f tls_record_size] [-c http_chunk_size] hostname http_request\n", prog);
  fprintf(stderr, "  %s --get [-r number_of_requests] hostname http_request\n", prog);
  fprintf(stderr, "Examples\n");
  fprintf(stderr, "  To send a file via POST with chunks of 64 o and TLS records size of 2 Ko:\n");
  fprintf(stderr, "    %s --send -f2048 -c64 192.168.210.5 \"POST /file.txt\" < file.txt\n", prog);
  fprintf(stderr, "  Same as previously, but with Content-Length field in request (non-conforme to HTTP/1.1 specifications):\n");
  fprintf(stderr, "    %s --send -l -f2048 -c64 192.168.210.5 \"POST /file.txt\" < file.txt\n", prog);
  fprintf(stderr, "  To send a file via POST without chunked encoding and the default TLS records size (16 Ko):\n");
  fprintf(stderr, "    %s --send 192.168.210.5 \"POST /file.txt\" < file.txt\n", prog);
  fprintf(stderr, "  To get a resource via GET:\n");
  fprintf(stderr, "    %s --get 192.168.210.5 \"GET /file.txt\"\n", prog);
  fprintf(stderr, "  Same as previously, but repeated 32 times:\n");
  fprintf(stderr, "    %s --get -r32 192.168.210.5 \"GET /file.txt\"\n", prog);
  fprintf(stderr, "Attention:\n");
  fprintf(stderr, "  - Sometimes we need to know the size to transmit in advance,"
                  " the standard input shall be a regular file (not the output of a pipe).\n");
}

typedef enum {
  UNKNOWN_OPERATION = 0,
  SEND_OPERATION = 1,
  GET_OPERATION = 2,
} OPERATION_E;
#define DEFAULT_MAXIMUM_FRAGMENT_SIZE (16384 - 16) /* 16Ko */

int main(int argc, char** argv)
{
  OPERATION_E operation;
  int option_index;
  int opt;

  const char* hostname;
  const char* request;
  unsigned int record_size;
  unsigned int chunk_size;
  unsigned int number_of_requests;
  bool force_send_file_length;

  #define CONF_STR_SIZE 32
  char conn_hostname_str[CONF_STR_SIZE];

  int ret;

  BIO* sbio;
  SSL_CTX* ctx;
  SSL* ssl;

  /* Parse the options and the arguments */
  static struct option long_options[] = {
    {"send", no_argument, NULL, SEND_OPERATION},
    {"get", no_argument, NULL, GET_OPERATION},
    {0, 0, 0, 0},
  };
  static const char* short_options = "f:c:r:";
  record_size = DEFAULT_MAXIMUM_FRAGMENT_SIZE;
  chunk_size = 0; /* disabled */
  number_of_requests = 1;
  force_send_file_length = false;
  operation = UNKNOWN_OPERATION;
  option_index = 0;
  while ((opt = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {
    switch (opt) {
      case SEND_OPERATION:
      case GET_OPERATION:
        operation = (OPERATION_E)(opt);
        break;

      case 'f':
        record_size = atoi(optarg);
        break;

      case 'c':
        chunk_size = atoi(optarg);
        break;

      case 'r':
        number_of_requests = atoi(optarg);
        break;

      case 'l':
        force_send_file_length = true;
        break;

      default:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  if (optind >= argc) {
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  hostname = argv[optind];
  request = argv[optind + 1];

  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  OpenSSL_add_all_algorithms();

  ctx = SSL_CTX_new(SSLv23_client_method());

  /* Configure the TLS connection */
  sbio = BIO_new_buffer_ssl_connect(ctx);
  BIO_get_ssl(sbio, &ssl);
  if (ssl == NULL) {
    fprintf(stderr, "Can't locate SSL pointer\n");
    BIO_free_all(sbio);
    exit(EXIT_FAILURE);
  }
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  /* Set server hostname */ 
  snprintf(conn_hostname_str, CONF_STR_SIZE, "%s:https", hostname);
  BIO_set_conn_hostname(sbio, conn_hostname_str);

  /* Initiate TLS handshake and connection */
  ret = BIO_do_handshake(sbio);
  if (ret <= 0) {
    fprintf(stderr, "Error during initialization of SSL connection and handshake\n");
    BIO_free_all(sbio);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  fprintf(stderr, "Connection and handshake done\n");

  switch (operation) {
    /* Send the standard input over the HTTPS connection */
    case SEND_OPERATION:
      if (chunk_size == 0) {
        send_data(sbio, request, stdin, record_size);
      } else {
        send_chunked_data(sbio, request, stdin, record_size, chunk_size, force_send_file_length);
      }
      break;

    /* Send a simple request several times */
    case GET_OPERATION:
      printf("Number of requests: %u\n", number_of_requests);
      for (int i = 0; i != number_of_requests; i++)
        get_resource(sbio, request);
      break;

    case UNKNOWN_OPERATION:
    default:
      fprintf(stderr, "Unknown operation\n");
      BIO_free_all(sbio);
      exit(EXIT_FAILURE);
  }

  BIO_free_all(sbio);
  exit(EXIT_SUCCESS);
}

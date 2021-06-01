#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <iostream>
#include <cstring>
#include <vector>
#include <ctime>
#include <unistd.h>
#include <openssl/sha.h>
#include <sstream>
#include <random>
#include <algorithm>
#include <functional>

#define FAIL -1

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";


std::string base64_encode(unsigned char const *bytes_to_encode,
                          unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] =
          ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] =
          ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++) ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 3; j++) char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] =
        ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] =
        ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++) ret += base64_chars[char_array_4[j]];

    while ((i++ < 3)) ret += '=';
  }

  return ret;
}
std::string GetHexRepresentation(const unsigned char *Bytes, size_t Length) {
  std::string ret(Length*2, '\0');
  const char *digits = "0123456789abcdef";
  for(size_t i = 0; i < Length; ++i) {
    ret[i*2]   = digits[(Bytes[i]>>4) & 0xf];
    ret[i*2+1] = digits[ Bytes[i]     & 0xf];
  }
  return ret;
}
std::string sha1(const std::string &input) {
  BIO *p_bio_md = nullptr;
  BIO *p_bio_mem = nullptr;

  try {
    // make chain: p_bio_md <-> p_bio_mem
    p_bio_md = BIO_new(BIO_f_md());
    if (!p_bio_md) throw std::bad_alloc();
    BIO_set_md(p_bio_md, EVP_sha1());

    p_bio_mem = BIO_new_mem_buf((void *)input.c_str(), input.length());
    if (!p_bio_mem) throw std::bad_alloc();
    BIO_push(p_bio_md, p_bio_mem);

    // read through p_bio_md
    // read sequence: buf <<-- p_bio_md <<-- p_bio_mem
    std::vector<char> buf(input.size());
    for (;;) {
      auto nread = BIO_read(p_bio_md, buf.data(), buf.size());
      if (nread < 0) {
        throw std::runtime_error("BIO_read failed");
      }
      if (nread == 0) {
        break;
      }  // eof
    }

    // get result
    char md_buf[EVP_MAX_MD_SIZE];
    auto md_len = BIO_gets(p_bio_md, md_buf, sizeof(md_buf));
    if (md_len <= 0) {
      throw std::runtime_error("BIO_gets failed");
    }

    std::string result(md_buf, md_len);

    // clean
    BIO_free_all(p_bio_md);
   
    return GetHexRepresentation((unsigned char *)result.c_str(), result.length());
    /*************************************/
    //return base64_encode((unsigned char const *)result.c_str(), sizeof(result));
    // return result;
  } catch (...) {
    if (p_bio_md) {
      BIO_free_all(p_bio_md);
    }
    throw;
  }
}

template <typename T = std::mt19937>
auto random_generator() -> T {
  auto constexpr seed_bytes = sizeof(typename T::result_type) * T::state_size;
  auto constexpr seed_len = seed_bytes / sizeof(std::seed_seq::result_type);
  auto seed = std::array<std::seed_seq::result_type, seed_len>();
  auto dev = std::random_device();
  std::generate_n(begin(seed), seed_len, std::ref(dev));
  auto seed_seq = std::seed_seq(begin(seed), end(seed));
  return T{seed_seq};
}
auto gen_random(std::size_t len) -> std::string {
  static constexpr auto chars =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
  thread_local auto rng = random_generator<>();
  auto dist = std::uniform_int_distribution{{}, std::strlen(chars) - 1};
  auto result = std::string(len, '\0');
  std::generate_n(begin(result), len, [&]() { return chars[dist(rng)]; });
  return result;
}
// Added the LoadCertificates how in the server-side makes.
void LoadCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile) {
  /* set the local certificate from CertFile */
  if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* verify private key */
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "Private key does not match the public certificate\n");
    abort();
  }
}

int OpenConnection(const char *hostname, int port) {
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;

  if ((host = gethostbyname(hostname)) == NULL) {
    perror(hostname);
    abort();
  }
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);
  if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(sd);
    perror(hostname);
    abort();
  }
  return sd;
}

SSL_CTX *InitCTX(void) {
  const SSL_METHOD *method = nullptr;
  SSL_CTX *ctx = nullptr;
  // SSL_METHOD *method;
  // SSL_CTX *ctx;


  OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */

  SSL_load_error_strings(); /* Bring in and register error messages */
  // method =TLSv1_2_method();
  method = SSLv23_client_method();
  // method=SSLv3_client_method(); /* Create new client-method instance */
  ctx = SSL_CTX_new(method); /* Create new context */

  if (ctx == nullptr) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}

void ShowCerts(SSL *ssl) {
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if (cert != nullptr) {
    printf("Server certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
    printf("Subject: %s\n", line);
    free(line); /* free the malloc'ed string */
    line = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
    printf("Issuer: %s\n", line);
    free(line); /* free the malloc'ed string */
    X509_free(cert); /* free the malloc'ed certificate copy */
  } else
    printf("No certificates.\n");
}

int main() {
  SSL_CTX *ctx;
  int server;
  SSL *ssl;
  char buf[4096];
  int bytes;
  char hostname[] = "18.202.148.130";
  // 3335, 8082, 8445, 49154, 3480, 65533
  char portnum[] = "3480";
  char CertFile[] = "cacert.pem";
  char KeyFile[] = "cakey.pem";

  SSL_library_init();

  ctx = InitCTX();
  LoadCertificates(ctx, CertFile, KeyFile);

  server = OpenConnection(hostname, atoi(portnum));

  ssl = SSL_new(ctx); /* create new SSL connection state */
  std::cout << "New SSL connection state is  :" << ssl << std::endl;
  SSL_set_fd(ssl, server); /* attach the socket descriptor */

  if (SSL_connect(ssl) == FAIL) { /* perform the connection */

    ERR_print_errors_fp(stderr);
  } else {
    const char* authdata{};
    while (true) {
      /**/
      printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
      ShowCerts(ssl);  // get any certs
      // SSL_write(ssl, msg, strlen(msg));   // encrypt & send message
      bytes = SSL_read(ssl, buf, sizeof(buf));  // get reply & decrypt */
      // buf[bytes] = 0;
      std::cout << "Received :" << buf << std::endl;
      // printf("Received: \"%s\"\n", buf);
      /**************************************************/
      std::vector<char *> v;
      char *chars_array = strtok(buf, " ");
      while (chars_array != NULL) {
        v.push_back(chars_array);
        chars_array = strtok(NULL, " ");
      }
      std::cout << "Printing vector values:" << std::endl;
      for (auto x : v) std::cout << x << std::endl;
      std::string check_sum{};
     // std::string authdata = v[1];
      std::string v0 = "HELO\n";
      std::string v1 = "ERROR\n";
      std::string v2 = "POW";
      std::string v3 = "END\n";
      std::string v4 = "NAME\n";
      std::string v5 = "MAILNUM\n";
      std::string v6 = "MAIL1\n";
      std::string v7 = "MAIL2\n";
      std::string v8 = "SKYPE\n";
      std::string v9 = "BIRTHDATE\n";
      std::string v10 = "COUNTRY\n";
      std::string v11 = "ADDRNUM\n";
      std::string v12 = "ADDRLINE1\n";
      std::string v13 = "ADDRLINE2\n";
      std::string str(v[0]);
      if (str == v0) {
        std::cout << "Congratulations! EHELO\n is written to server"
                  << std::endl;
        SSL_write(ssl, "EHLO\n", strlen("EHLO\n"));

      } else if (v[0] == "ERROR\n") {
        std::cout << "ERROR: " << v[1];
        break;
      } else if (str == v2 &&v.size ()>1) /*(v[0] == "POW\n")*/ {

        std::string suffix = "";
        std::string autdata_internal = "";
        std::stringstream ss{};
        std::string rndm{};
        std::string mystr{};
        size_t count_of_leading_zeros = 0;
        //char *check_sum2 = "";
        while (true) {
          if(v.size ()>1){
          autdata_internal = v[1];
          authdata = v[1];
          }
          rndm.clear ();
          rndm = gen_random(64);
          std::cout << "Random string is :  " << rndm << std::endl;
          //suffix = rndm;
          std::cout << "authdata is :  " << authdata << std::endl;
          std::cout << "autdata_internal is :  " << autdata_internal
                    << std::endl;
          // std::strcat(autdata_internal, suffix);
          autdata_internal += rndm;//suffix;


          //count_of_leading_zeros = 0;
          check_sum = sha1(autdata_internal);
        
          std::cout << "Checksum is :  " << check_sum << std::endl;
          
          for (size_t i = 0; i < 2; ++i) {
            if (check_sum[i] == '0')
          ++count_of_leading_zeros;
          }
           std::cout << "Leadind 0s  " << count_of_leading_zeros << std::endl;
          if (count_of_leading_zeros == 2) {
           //rndm+= "\n";//std::strcat(suffix, "\n");
            SSL_write(ssl, rndm.c_str (), strlen(rndm.c_str ()));
            std::cout << "SSL_write written  " << rndm.c_str () << std::endl;
            break;
          }

          autdata_internal.clear ();

          //suffix.clear ();
          check_sum.clear ();
          mystr.clear ();
          count_of_leading_zeros = 0;
          rndm.clear();
          //check_sum2 = "";
        }
      }

        else if (v[0] == "END") {
            SSL_write(ssl, "OK\n", strlen("OK\n"));
            std::cout << "ENDing......  " << std::endl;
            break;
      } else if (v[0] == "NAME") {
            //std::strcat(authdata, v[1]);
            std::cout << "authdata :  " <<authdata
                      << std::endl;
            std::string str(authdata);
            str += v[1];
            std::string my_name = " Tadewos Somano\n";
            check_sum = sha1(str);
            // sha1(authdata, check_sum);
            // std::strcat(check_sum, my_name);
            check_sum += my_name;
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            std::cout << "Written NAME......  " <<(char *)check_sum.c_str()<< std::endl;
            break;
          } else if (v[0] == "MAILNUM") {
            // std::strcat(authdata, v[1]);
            std::cout << "authdata :  " <<authdata
                      << std::endl;
            std::string str(authdata);
            str += v[1];
            std::string my = " 2\n";
            check_sum = sha1(str);
            check_sum += my;
            // sha1(authdata, check_sum);
            // std::strcat(check_sum, my);
            SSL_write(ssl, check_sum.c_str (), strlen(check_sum.c_str ()));
            std::cout << "MAILNUMing......  " << std::endl;
            break;
          } else if (v[0] == "MAIL1") {
            // std::strcat(authdata, v[1]);
            std::cout << "authdata :  " <<authdata
                      << std::endl;
            std::string str(authdata);
            str += v[1];
            std::string my_email = " tadewos85@gmail.com\n";
            // sha1(authdata, check_sum);
            check_sum = sha1(str);
            // std::strcat(check_sum, my_email);
            check_sum += my_email;
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            // SSL_write(ssl, check_sum, strlen(check_sum));
            std::cout << "MAIL1ing......  " << std::endl;
            break;
          } else if (v[0] == "MAIL2") {
            // std::strcat(authdata, v[1]);
            std::cout << "authdata :  " <<authdata
                      << std::endl;
            std::string str(authdata);
            str += v[1];
            std::string my_email2 = " tadewos_somano.ewalo@akka.eu\n";
            // sha1(authdata, check_sum);
            check_sum = sha1(str);
            // std::strcat(check_sum, my_email2);
            check_sum += my_email2;
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            // SSL_write(ssl, check_sum, strlen(check_sum));
            std::cout << "MAIL2ing......  " << std::endl;
            break;
          } else if (v[0] == "SKYPE") {
            // std::strcat(authdata, v[1]);
            std::cout << "authdata :  " <<authdata
                      << std::endl;
            std::string str(authdata);
            str += v[1];
            std::string my_skype = " tadewossomano\n";
            // sha1(authdata, check_sum);
            check_sum = sha1(str);
            // std::strcat(check_sum, my_skype);
            check_sum += my_skype;
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            // SSL_write(ssl, check_sum, strlen(check_sum));
            std::cout << "SKYPEing......  " << std::endl;
            break;
          } else if (v[0] == "BIRTHDATE") {
            // std::strcat(authdata, v[1]);
            std::cout << "authdata :  " <<authdata
                      << std::endl;
            std::string str(authdata);
            str += v[1];
            std::string my_birthdate = " 21.01.1985\n";
            // sha1(authdata, check_sum);
            check_sum = sha1(str);
            // std::strcat(check_sum, my_birthdate);
            check_sum += my_birthdate;
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            // SSL_write(ssl, check_sum, strlen(check_sum));
            std::cout << "BIRTHDATEing......  " << std::endl;
            break;
          } else if (v[0] == "COUNTRY") {

            std::cout << "authdata :  " <<authdata
                      << std::endl;
            std::string str(authdata);
            str += v[1];
            std::string my_country = " ITALY\n";

            check_sum = sha1(str);

            check_sum += my_country;
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            // SSL_write(ssl, check_sum, strlen(check_sum));
            std::cout << "COUNTRYing......  " << std::endl;
            break;
          } else if (v[0] == "ADDRNUM") {

            std::cout << "authdata :  " <<authdata
                      << std::endl;
            std::string str(authdata);
            str += v[1];
            std::string my_address_num = " 2\n";

            check_sum = sha1(str);
            check_sum += my_address_num;
            //std::strcat(check_sum, my_address_num);
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            // SSL_write(ssl, check_sum, strlen(check_sum));
            std::cout << "ADDRNUMing......  " << std::endl;
            break;
          } else if (v[0] == "ADDRLINE1") {
            std::cout << "authdata :  " <<authdata
                      << std::endl;
            // std::strcat(authdata, v[1]);
            std::string(authdata);
            str += v[1];
            std::string my_address_num = " via Enrico Dandolo 21B\n";
            // sha1(authdata, check_sum);
            check_sum = sha1(str);
            check_sum += my_address_num;
            //std::strcat(check_sum, my_address_num);
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            // SSL_write(ssl, check_sum, strlen(check_sum));
            std::cout << "ADDRLINE1ing......  " << std::endl;
            break;
          } else if (v[0] == "ADDRLINE2") {
            std::cout << "authdata :  " <<authdata
                      << std::endl;
            // std::strcat(authdata, v[1]);
            std::string str(authdata);
            str += v[1];
            std::string my_address_num =
                " CORSO ENRICO TAZZOLI 215/12 /B 10137\n";
            // sha1(authdata, check_sum);
            check_sum = sha1(str);
            check_sum += my_address_num;
            //std::strcat(check_sum, my_address_num);
            SSL_write(ssl, check_sum.c_str(),
                      strlen((char *)check_sum.c_str()));
            //SSL_write(ssl, check_sum, strlen(check_sum));
            std::cout << "ADDRLINE2ing......  " << std::endl;
            break;
          }
        }

    printf("Received: \"%s\"\n", buf);

    SSL_free(ssl);        /* release connection state */
  }
  close(server);         /* close socket */
  SSL_CTX_free(ctx);        /* release context */
  return 0;
}

#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  //std::vector<uint8_t> message(65536);
  char buf[4096];
  sadb_msg msg{};
  // TODO: Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_UNSPEC;
  msg.sadb_msg_len = sizeof(sadb_msg)/8;
  msg.sadb_msg_pid = getpid();

  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information
  int sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  checkError(write(sock, &msg, sizeof(msg)), "Failed to write sock");
  // TODO: Set size to number of bytes in response message
  int size = read(sock, buf, sizeof(buf));
  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    // format: base + sa ext + src ext + dst ext + "key ext"
    char *p = buf + sizeof(sadb_msg); // begin of the extensions part
    bool getkey = false;
    uint8_t auth, enc;
    uint8_t key[128];
    int key_len;

    while (!getkey) {
      uint16_t type = *(p + sizeof(uint16_t));
      switch (type) {
        case SADB_EXT_SA: {
          struct sadb_sa* sa = (struct sadb_sa*)p;
          config.spi = sa->sadb_sa_spi;
          auth = sa->sadb_sa_auth;
          enc = sa->sadb_sa_encrypt;
          p += sa->sadb_sa_len * 8;
          break;
        }
        case SADB_EXT_ADDRESS_SRC: {
          struct sadb_address* addr = (struct sadb_address*)p;
          struct sockaddr_in* s = (struct sockaddr_in*) (addr + 1);
          config.remote = ipToString((uint32_t)s->sin_addr.s_addr);
          p += addr->sadb_address_len * 8;
          break;
        }
        case SADB_EXT_ADDRESS_DST: {
          struct sadb_address* addr = (struct sadb_address*)p;
          struct sockaddr_in* s = (struct sockaddr_in*) (addr + 1);
          config.local = ipToString((uint32_t)s->sin_addr.s_addr);
          p += addr->sadb_address_len * 8;
          break;
        }
        case SADB_EXT_KEY_AUTH: {
          struct sadb_key* k = (struct sadb_key*)p;
          key_len = k->sadb_key_bits / 8;
          memcpy(key, k + 1, key_len);
          getkey = true;
          break;
        }
        case SADB_EXT_LIFETIME_CURRENT: {
          struct sadb_lifetime* lf = (struct sadb_lifetime*)p;
          p += lf->sadb_lifetime_len * 8;
          break;
        }
        case SADB_EXT_LIFETIME_HARD:{
          struct sadb_lifetime* lf = (struct sadb_lifetime*)p;
          p += lf->sadb_lifetime_len * 8;
          break;
        }
        case SADB_EXT_LIFETIME_SOFT:{
          struct sadb_lifetime* lf = (struct sadb_lifetime*)p;
          p += lf->sadb_lifetime_len * 8;
          break;
        }
        default:
          break;
      }
    }
    std::span<uint8_t> _key(key, key+key_len);
    config.aalg = std::make_unique<ESP_AALG>((int)auth, _key);
    // Have enc algorithm:
    config.ealg = std::make_unique<ESP_EALG>((int)enc, _key);
    // No enc algorithm:
    config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});

    close(sock);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}

#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <utility>
#include <arpa/inet.h>

extern bool running;

Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  if (hdr.saddr == stringToIPv4(config.remote).s_addr) state.recvPacket = true;
  
  // Track current IP id
  state.ipId = hdr.id;

  // Call dissectESP(payload) if next protocol is ESP
  auto payload = buffer.last(buffer.size() - (hdr.ihl << 2));
  auto &&next_hdr = reinterpret_cast<ESPHeader*>(payload.data());
  if(hdr.protocol == IPPROTO_ESP) {
    dissectESP(payload);
  }
}

void Session::dissectESP(std::span<uint8_t> buffer) {
  
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  
  // Strip hash
  auto payload = buffer.subspan(sizeof(ESPHeader), buffer.size()- sizeof(ESPHeader) - hashLength);

  // Decrypt payload
  if (!config.ealg->empty()) {
    auto result = config.ealg->decrypt(payload);
    std::copy(result.begin(), result.end(), payload.begin());
  }  

  // TODO:
  // Track ESP sequence number
  state.espseq = hdr.seq;

  // Call dissectTCP(payload) if next protocol is TCP
  dissectTCP(payload);
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  state.tcpseq = hdr.seq;
  state.tcpackseq = hdr.ack_seq;
  state.srcPort = hdr.source;
  state.dstPort = hdr.dest;

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    state.sendAck = true;
    std::cout << "payload size: " << payload.size() << std::endl;
    std::cout << "Secret received: " << std::string(payload.begin(), payload.end()) << "\n";
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

void printbit(uint16_t n){
  for(int i=0;i<16;++i){
    std::cout << (n & 1);
    n >>= 1;
  }
}
uint16_t ipv4_checksum(uint16_t* buffer, int size) {
  uint32_t sum = 0;
  for (int i = 0; i < size; i++) {
    sum += buffer[i];
  }
  sum = (sum & 0xFFFF) + (sum >> 16);
  return ~sum;
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  
  // TODO: Fill IP header
  hdr.version = 4; 
  hdr.ihl = 5; 
  hdr.ttl = 64;
  hdr.id = state.ipId;
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = 0;
  hdr.saddr = htonl(stringToIPv4(config.local).s_addr);
  hdr.daddr = htonl(stringToIPv4(config.remote).s_addr);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);

  // TODO: Compute checksum, IP check sum computes the ckecksum of the header
  hdr.check = 0;
  hdr.check = ipv4_checksum(reinterpret_cast<uint16_t*>(&hdr), sizeof(iphdr)/2);
  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  
  // TODO: Fill ESP header
  hdr.spi = config.spi;
  hdr.seq = state.espseq;
  int payloadLength = encapsulateTCP(nextBuffer, payload);
  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);

  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = 4- (payloadLength+sizeof(ESPTrailer)) % 4;
  payloadLength += padSize;

  // ESP trailer
  endBuffer[padSize] = padSize;
  endBuffer[padSize + 1] = IPPROTO_TCP;
  payloadLength += sizeof(ESPTrailer);

  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  // TODO: Fill in config.aalg->hash()'s parameter
  if (!config.aalg->empty()) {
    auto result = config.aalg->hash(buffer.first(payloadLength));
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }
  return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;

  // TODO: Fill TCP header
  hdr.ack = state.sendAck;
  hdr.doff = htons(5);
  hdr.dest = state.srcPort;
  hdr.source = state.dstPort;
  hdr.ack_seq = state.tcpackseq;
  hdr.seq = state.tcpseq;
  hdr.window = htons(1024);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }

  // TODO: Update TCP sequence number
  state.tcpseq = hdr.seq;
  payloadLength += sizeof(tcphdr);
  
  // TODO: Compute checksum, TCP check sum computes the ckecksum of the whole packet
  hdr.check = 0;
  for (int i = 0; i < payloadLength; i += 2) {
    hdr.check += (uint16_t) (nextBuffer[i] << 8 | nextBuffer[i + 1]);
  }
  return payloadLength;
}

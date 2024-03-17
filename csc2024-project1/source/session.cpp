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
  if (hdr.saddr == stringToIPv4(config.remote).s_addr) 
    state.recvPacket = true;
  else 
    state.recvPacket = false;
   
  // Track current IP id
  if(hdr.saddr == stringToIPv4(config.local).s_addr) 
    state.ipId = hdr.id;

  // Call dissectESP(payload) if next protocol is ESP
  auto payload = buffer.last(buffer.size() - (hdr.ihl << 2));
  auto &&next_hdr = reinterpret_cast<ESPHeader*>(payload.data());
  if(hdr.protocol == IPPROTO_ESP){
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
  if(!state.recvPacket){
    state.espseq = hdr.seq;
    config.spi = hdr.spi;
  }

  // Call dissectTCP(payload) if next protocol is TCP
  auto next_hdr = payload.data()[payload.size()-1];
  uint8_t padSize = payload.data()[payload.size()-2];
  if(next_hdr == IPPROTO_TCP){
    payload = payload.first(payload.size()-sizeof(ESPTrailer)-padSize);
    dissectTCP(payload);
  }
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  
  // Track tcp parameters
  if(state.recvPacket) {
    state.tcpseq = ntohl(hdr.ack_seq);
    state.tcpackseq = ntohl(hdr.seq) + payload.size();
    state.srcPort = hdr.dest;
    state.dstPort = hdr.source;
  }

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    state.sendAck = true;
    std::cout << "Secret received: " << std::string(payload.begin(), payload.end()) << std::endl;
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}


int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  
  // TODO: Fill IP header
  hdr.version = 4; 
  hdr.ihl = 5; 
  hdr.ttl = 64;
  hdr.id = state.ipId + 1;
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = 0;
  hdr.saddr = stringToIPv4(config.local).s_addr; 
  hdr.daddr = stringToIPv4(config.remote).s_addr;
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);

  // TODO: Compute checksum, IP check sum computes the ckecksum of the header
  hdr.check = 0;
  uint32_t checksum = 0;
  for(int i=0;i<sizeof(iphdr)/2;i++) {
    checksum += (buffer[i*2+1] << 8) + buffer[i*2];
  }
  checksum = (checksum & 0xFFFF) + (checksum >> 16);
  hdr.check = ~checksum;
  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  
  // TODO: Fill ESP header
  hdr.spi = config.spi;
  hdr.seq = state.espseq + htonl(1);
  int payloadLength = encapsulateTCP(nextBuffer, payload);
  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);

  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = 6 - payloadLength % 4;
  payloadLength += padSize;
  for(int i = 0; i < padSize; i++) {
    endBuffer[i] = i+1;
  }

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
  hdr.ack = 1;
  hdr.doff = 5;
  hdr.dest = state.dstPort;
  hdr.source = state.srcPort;
  hdr.ack_seq = htonl(state.tcpackseq);
  hdr.seq = htonl(state.tcpseq);
  hdr.window = htons(502);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }

  // TODO: Update TCP sequence number
  state.tcpseq += payloadLength; //  ????
  payloadLength += sizeof(tcphdr);
  
  // TODO: Compute checksum, TCP check sum computes the ckecksum of the whole packet
  hdr.check = 0;
  uint32_t checksum = 0;
  checksum += stringToIPv4(config.local).s_addr & 0xFFFF; 
  checksum += stringToIPv4(config.local).s_addr >> 16;  
  checksum += stringToIPv4(config.remote).s_addr & 0xFFFF;
  checksum += stringToIPv4(config.remote).s_addr >> 16;
  checksum += htons(IPPROTO_TCP);
  checksum += htons(payloadLength);

  // calculate header cksum
  for(int i=0;i<sizeof(tcphdr)/2;i++) {
    checksum += (buffer[i*2+1] << 8) + buffer[i*2];
  }
  // calculate payload cksum
  for(int i = 0; i < payloadLength/2; ++i) {
    checksum += (nextBuffer[i*2+1] << 8) + nextBuffer[i*2];
  }
  if(payloadLength % 2 != 0) {
    checksum += nextBuffer[payloadLength - 1]; 
  }
  checksum = (checksum & 0xFFFF) + (checksum >> 16);
  hdr.check = ~checksum;

  return payloadLength;
}

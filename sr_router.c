/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
 #include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

 
 #define TTL 64

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/* Helper function to get an interface from a next hop IP address */
char * sr_get_iface_from_gw_ip(struct sr_instance *sr, uint32_t ip){
    struct sr_rt* curr = sr->routing_table;
    while(curr){
        if(curr->gw.s_addr == ip)return curr->interface;
        curr = curr->next;
    }
    return NULL;
}

/* Sends an ethernet frame. Takes in an the data and the MAC address destination and the interface through
which to send it */
void sr_send_eth(struct sr_instance *sr, uint8_t *buf, unsigned int len, uint8_t *destination,
              char *iface, enum sr_ethertype type){

  unsigned int total_size = len + sizeof(sr_ethernet_hdr_t);
  uint8_t *eth = malloc(total_size);
  memcpy(eth + sizeof(sr_ethernet_hdr_t), buf, len);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)eth;
  

  unsigned char * addr = sr_iface_to_mac(sr, iface);

  memcpy(eth_hdr->ether_dhost, destination, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(type);

  sr_send_packet(sr, eth, total_size, iface);

  free(eth);

}

/* Sends an IP packet. Builds an IP and populates the fields accordingly */
void sr_send_ip(struct sr_instance *sr, enum sr_ip_protocol protocol, uint32_t source, uint32_t dest, uint8_t *buf, unsigned int len){

  struct sr_rt * rt_node = longest_prefix_match(sr, dest);

  if(!rt_node){
    fprintf(stderr, "No match in routing table.....should return because otherwise would send message to self\n");
    return;
  }

  struct sr_if * if_node = sr_get_interface(sr, rt_node->interface);
  if(!if_node)return;

  int ip_len = sizeof(sr_ip_hdr_t);

  struct sr_ethernet_hdr *eth = calloc(sizeof(sr_ethernet_hdr_t) + ip_len + len, sizeof(uint8_t));
  struct sr_ip_hdr *ip = (sr_ip_hdr_t *)(eth + 1);
  memcpy(ip + 1, buf, len);

  ip->ip_v = ip_v;
  ip->ip_off = htons(IP_DF);
  ip->ip_hl = MIN_IP_HEADER_SIZE;
  ip->ip_p = protocol;
  ip->ip_src = source;
  ip->ip_dst = dest;
  ip->ip_len = htons(ip_len + len);
  ip->ip_ttl = TTL;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, ip_len);

  eth->ether_type = htons(ethertype_ip);
  memcpy(eth->ether_shost, if_node->addr, ETHER_ADDR_LEN); 
  
  sr_attempt_send(sr, rt_node->gw.s_addr, (uint8_t *)eth, sizeof(sr_ethernet_hdr_t)+ip_len+len, if_node->name);

  free(eth);


}

/* Sends an ICMP packet that is not of type 3*/
void sr_send_icmp(struct sr_instance *sr, enum sr_icmp_type type, enum sr_icmp_code code, uint32_t ip_source, uint32_t ip_dest, uint8_t *buf, unsigned int len){

  int icmp_len = sizeof(sr_icmp_hdr_t) + len;
  struct sr_icmp_hdr *icmp = calloc(icmp_len, 1);
  memcpy(icmp+1, buf, len);
  icmp->icmp_type = type;
  icmp->icmp_code = code;
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, icmp_len);
  
  sr_send_ip(sr, ip_protocol_icmp, ip_source, ip_dest, (uint8_t *)icmp, icmp_len);

  free(icmp);

}

/* Sends an ICMP packet of type 3*/
void sr_send_icmp3(struct sr_instance *sr, enum sr_icmp_type type, enum sr_icmp_code code, uint32_t ip_source, uint32_t ip_dest, uint8_t *data, unsigned int len){
  int icmp_len = sizeof(sr_icmp_t3_hdr_t);

  struct sr_icmp_t3_hdr *icmp = calloc(1,icmp_len);
  memcpy(icmp->data, data, len);
  icmp->icmp_type = type;
  icmp->icmp_code = code;
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, icmp_len);
  
  sr_send_ip(sr, ip_protocol_icmp, ip_source, ip_dest, (uint8_t *)icmp, icmp_len);

  free(icmp);
}

unsigned char * sr_iface_to_mac(struct sr_instance *sr, char *interface){
  struct sr_if *node = sr->if_list;
  while(node){
    if(strcmp(node->name, interface) == 0){
        return node->addr;
    }
    node = node->next;
  }
  return NULL;
}

/* Handles ARP packets. Calls recv_arp to store information from ARP in the cache. Then, if it is a request, sends reply
else, we can just return */
void sr_handle_arp_packet(struct sr_instance* sr, struct sr_arp_hdr * arp_packet, unsigned int len, char* interface){
  int min_length = sizeof(sr_arp_hdr_t);
  if (len < min_length) {
    fprintf(stderr, "ARP Packet too small - returning...\n");
    return;
  }

  struct sr_if* node = sr_get_interface(sr, interface);


  if(node->ip == arp_packet->ar_tip){
    sr_recv_arp(sr, arp_packet);

    if(ntohs(arp_packet->ar_op) == arp_op_request){

      sr_send_arp_reply(sr, interface, arp_packet->ar_sha, arp_packet->ar_sip);
    }else if(ntohs(arp_packet->ar_op) == arp_op_reply){
      // do nothing
    }

  }else{
    fprintf(stderr, "ARP NOT for me\n");
  }

}

/* Handles an IP packet that is meant for me 
  If it is ICMP echo, then we send reply, otherwise, if it is TCP or UDP, 
  we send an port unreachable back to sender
*/
void sr_ip_packet_for_me(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr){

    unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;
    uint8_t *ip_payload = ((uint8_t *)ip_hdr) + ip_hdr_len;
    if(ip_hdr->ip_p == ip_protocol_icmp){

      struct sr_icmp_hdr * icmp_hdr = (sr_icmp_hdr_t *)(ip_payload);
      unsigned int icmp_payload_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - sizeof(sr_icmp_hdr_t);

      if(icmp_hdr->icmp_type == icmp_echo_request){

        sr_send_icmp(sr, icmp_echo_reply, icmp_echo_reply_code, ip_hdr->ip_dst, ip_hdr->ip_src, (uint8_t *)(icmp_hdr+1), icmp_payload_len);  
      }
      
    }else{
      //Assuming its TCP or UDP
      fprintf(stderr, "Its NOT an ICMP packet! Send Unreachable!!\n");
      sr_send_icmp3(sr, icmp_unreach, icmp_port_unreach, ip_hdr->ip_dst, ip_hdr->ip_src, (uint8_t*)ip_hdr, ip_hdr_len + MORSEL);
    }
}

/* Checks to see if a given IP packet was meant for me */
struct sr_if * sr_packet_is_for_me(struct sr_instance *sr, uint32_t ip_dest){
  struct sr_if *node = sr->if_list;
  while(node){
    if(node->ip == ip_dest)return node;
    node = node->next;
  }
  return NULL;
}


/* Handles an IP packet.

First checks to see whether it is for me. If not, decrement TTL and recompute checksum. Then figure out 
where to forward it */

void sr_handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){

    int min_length = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
    if (len < min_length) {
      fprintf(stderr, "IP Packet too small - returning...\n");
      return;
    }

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    unsigned int ip_hdr_len = iphdr->ip_hl * 4;

    struct sr_if *my_node = sr_packet_is_for_me(sr, iphdr->ip_dst);
    if(my_node){
      fprintf(stderr, "IP packet is for us\n");
      sr_ip_packet_for_me(sr, iphdr);
      return;
    }

     uint8_t new_ttl = iphdr->ip_ttl - 1;
     if(new_ttl == 0){
       fprintf(stderr, "TTL hit zero, sending an ICMP back....\n");
       uint8_t * buf = calloc(4 + ip_hdr_len + MORSEL, 1);
       memcpy(buf + 4, iphdr, ip_hdr_len + MORSEL);
       sr_send_icmp(sr, icmp_ttl, icmp_ttl_code, iphdr->ip_dst, iphdr->ip_src, buf, 4 + ip_hdr_len + MORSEL);
       free(buf);
       return;
     }

     iphdr->ip_ttl = new_ttl;

     iphdr->ip_sum = 0;
     iphdr->ip_sum = cksum(iphdr, ip_hdr_len);

    struct sr_rt *match = longest_prefix_match(sr, iphdr->ip_dst);
    if(match){

      uint8_t *temp = malloc(len);
      if(!temp)return;
      
      memcpy(temp, packet, len);

      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)temp;
      
      struct sr_if * node = sr_get_interface(sr, match->interface);
      memcpy(eth_hdr->ether_shost, node->addr, ETHER_ADDR_LEN);

      sr_attempt_send(sr, match->gw.s_addr, temp, len, match->interface);
      free(temp);
    }else{
      fprintf(stderr, "No routing table match, send ICMP\n");
      struct sr_if *my_source = sr_get_interface(sr, interface);
      sr_send_icmp3(sr, icmp_unreach, icmp_network_unreach, my_source->ip, iphdr->ip_src, (uint8_t*)iphdr, ip_hdr_len + MORSEL);
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  
  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);
  int min_length  = sizeof(sr_ethernet_hdr_t);
  if(len < min_length){
    fprintf(stderr,"Ethernet Packet too small - returning...\n");
    return;
  }

  uint16_t ethtype = ethertype(packet);

  if(ethtype == ethertype_ip){

    sr_handle_ip_packet(sr, packet, len, interface);
  }else if(ethtype == ethertype_arp){

    sr_handle_arp_packet(sr, (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), len - sizeof(sr_ethernet_hdr_t), interface);
  }


}/* end sr_ForwardPacket */


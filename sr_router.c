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


char * sr_get_iface_from_gw_ip(struct sr_instance *sr, uint32_t ip){
    struct sr_rt* curr = sr->routing_table;
    while(curr){
        if(curr->gw.s_addr == ip)return curr->interface;
        curr = curr->next;
    }
    return NULL;
}


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
  print_hdr_eth(eth);
  sr_send_packet(sr, eth, total_size, iface);
  free(eth);
}

void sr_send_ip(struct sr_instance *sr, uint8_t ttl, enum sr_ip_protocol protocol, uint32_t dest, uint8_t *buf, unsigned int len){
  int ip_len = sizeof(sr_ip_hdr_t);
  struct sr_ip_hdr *ip = calloc(ip_len + len, sizeof(uint8_t));


  struct sr_rt * rt_node = longest_prefix_match(sr, dest);
  struct sr_if * if_node = sr_get_interface(sr, rt_node->interface);
  //check NULL return
  ip->ip_p = htons(protocol);
  ip->ip_src = if_node->ip;
  ip->ip_dst = rt_node->gw.s_addr;
  ip->ip_len = htons(ip_len + len);
  ip->ip_ttl = ntohs(ttl);
  ip->ip_sum = cksum(ip, ip_len + len);

  fprintf(stderr, "-------------Sending this IP header----------------------------\n");
  print_hdr_ip((uint8_t *)ip);

  sr_send_eth(sr, (uint8_t *)ip, ip_len+len, if_node->addr, if_node->name, ethertype_ip);

  free(ip);


}

void sr_send_icmp(struct sr_instance *sr, enum sr_icmp_type type, enum sr_icmp_code code, uint32_t ip_dest){
  int icmp_len = sizeof(sr_icmp_hdr_t);
  struct sr_icmp_hdr *icmp = malloc(icmp_len);
  icmp->icmp_type = htons(type);
  icmp->icmp_code = htons(code);
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, icmp_len);
  fprintf(stderr, "-------------Sending this ICMP header----------------------------\n");
  print_hdr_icmp((uint8_t *)icmp);
  sr_send_ip(sr, 0, ip_protocol_icmp, ip_dest, (uint8_t *)icmp, icmp_len);

  free(icmp);

}

void sr_send_icmp3(struct sr_instance *sr, uint8_t type, uint8_t code, uint16_t unused, uint16_t next_mtu, uint8_t *data){

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

void sr_handle_arp_packet(struct sr_instance* sr, struct sr_arp_hdr * arp_packet, unsigned int len, char* interface){
  int min_length = sizeof(sr_arp_hdr_t);
  if (len < min_length) {
    fprintf(stderr, "ARP Packet too small - returning...\n");
    return;
  }
  print_hdr_arp((uint8_t *) arp_packet);

  struct sr_if* node = sr_get_interface(sr, interface);


  if(node->ip == arp_packet->ar_tip){
    fprintf(stderr, "ARP is for me at %s\n", interface);
    sr_recv_arp(sr, arp_packet);

    if(ntohs(arp_packet->ar_op) == arp_op_request){
      fprintf(stderr, "It's an ARP request....lets send a reply\n");
      sr_send_arp_reply(sr, interface, arp_packet->ar_sha, arp_packet->ar_sip);
    }else if(ntohs(arp_packet->ar_op) == arp_op_reply){
      fprintf(stderr, "It's a ARP reply so we're done!\n");
    }

  }else{
    fprintf(stderr, "ARP NOT for me\n");
  }

}

void sr_ip_packet_for_me(struct sr_instance *sr, struct sr_ip_hdr *ip_hdr){
    if(ntohs(ip_hdr->ip_p) == ip_protocol_icmp){
      struct sr_icmp_hdr * icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + 1);
      print_hdr_icmp((uint8_t *)icmp_hdr);
      if(ntohs(icmp_hdr->icmp_type) == icmp_echo_request){
        fprintf(stderr, "-----------------It's an ICMP Echo request---------------\n");
        sr_send_icmp(sr, icmp_echo_reply, icmp_echo_reply_code, ip_hdr->ip_src);  
      }
      
    }else{
      sr_send_icmp(sr, icmp_unreach, icmp_port_unreach, ip_hdr->ip_src);
    }
}

void sr_handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){

    int min_length = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
    if (len < min_length) {
      fprintf(stderr, "IP Packet too small - returning...\n");
      return;
    }
    print_hdrs(packet, len);
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    struct sr_if * my_node = sr_get_interface(sr, interface);
    if(iphdr->ip_dst == my_node->ip){
      fprintf(stderr, "IP packet is for us\n");
      sr_ip_packet_for_me(sr, iphdr);
    }

    // iphdr->ip_ttl--;
    // if(iphdr->ip_ttl == 0){
    //   fprintf(stderr, "TTL hit zero, sending an ICMP back....\n");
    //   sr_send_icmp(sr, icmp_ttl, icmp_ttl_code, iphdr->ip_src);
    //   return;
    // }

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
    }
    //sr_arpcache_dump(&(sr->cache));
    sr_print_queue(&(sr->cache));
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
  //print_hdrs(packet, len);
  int min_length  = sizeof(sr_ethernet_hdr_t);
  if(len < min_length){
    fprintf(stderr,"Ethernet Packet too small - returning...\n");
    return;
  }

  // uint8_t *temp = malloc(len);
  // if(temp){
  //   memcpy(temp, packet, len);
  //   packet = temp;
  // }

  uint16_t ethtype = ethertype(packet);

  if(ethtype == ethertype_ip){
    fprintf(stderr, "We have an IP packet\n");
    sr_handle_ip_packet(sr, packet, len, interface);
  }else if(ethtype == ethertype_arp){
    fprintf(stderr, "We have an ARP packet\n");
    sr_handle_arp_packet(sr, (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), len - sizeof(sr_ethernet_hdr_t), interface);
  }

  /* fill in code here */

}/* end sr_ForwardPacket */


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

char * sr_get_iface_from_ip(struct sr_instance *sr, uint32_t ip){
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

  if(strcmp(interface, sr_get_iface_from_ip(sr, arp_packet->ar_tip)) == 0){
    fprintf(stderr, "ARP is for me at %s\n", interface);
    sr_recv_arp(sr, arp_packet);

    if(arp_packet->ar_op == arp_op_request){
      fprintf(stderr, "It's an ARP request....lets send a reply\n");
    }else{
      fprintf(stderr, "It's a ARP reply so we're done!\n");
    }

  }else{
    fprintf(stderr, "ARP NOT for me\n");
  }



}

void sr_handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){

    int min_length = sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t);
    if (len < min_length) {
      fprintf(stderr, "IP Packet too small - returning...\n");
      return;
    }
    
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t ip_dst = iphdr->ip_dst;
    fprintf(stderr, "destination IP is: %u\n", ip_dst);
    struct in_addr address;
    address.s_addr = ip_dst;

    char outgoing_iface[sr_IFACE_NAMELEN];
    bool found = longest_prefix_match(sr, address, outgoing_iface);
    if(found){
      fprintf(stderr, "Outgoing Interface is: %s\n", outgoing_iface);

      uint8_t *temp = malloc(len);
      if(!temp)return;
      
      memcpy(temp, packet, len);

      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)temp;
      
      struct sr_if * node = sr_get_interface(sr, outgoing_iface);
      memcpy(eth_hdr->ether_shost, node->addr, ETHER_ADDR_LEN);

      sr_attempt_send(sr, ip_dst, temp, len, outgoing_iface);
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
  print_hdrs(packet, len);
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
    sr_handle_arp_packet(sr, (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)), len, interface);
  }

  /* fill in code here */

}/* end sr_ForwardPacket */


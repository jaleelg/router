#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

#include "sr_utils.h"

void sr_send_arp(struct sr_instance *sr, enum sr_arp_opcode code, char *iface, unsigned char *target_eth_addr, uint32_t target_ip){
    //fprintf(stderr, "\n-----------------------------------IN SEND ARP----------------------\n");
    sr_arp_hdr_t *arp_hdr = malloc(sizeof(sr_arp_hdr_t));
    if(arp_hdr){
        arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
        arp_hdr->ar_pro = htons(ethertype_ip);
        arp_hdr->ar_hln = ETHER_ADDR_LEN;
        arp_hdr->ar_pln = 4;
        arp_hdr->ar_op = htons(code);

        struct sr_if *node = sr_get_interface(sr, iface);

        memcpy(arp_hdr->ar_sha, node->addr, ETHER_ADDR_LEN);
        arp_hdr->ar_sip = node->ip;
        memcpy(arp_hdr->ar_tha, target_eth_addr, ETHER_ADDR_LEN);
        arp_hdr->ar_tip = target_ip;
        //print_hdr_arp((uint8_t *)arp_hdr);

        sr_send_eth(sr, (uint8_t *)arp_hdr, sizeof(sr_arp_hdr_t), (uint8_t *)target_eth_addr, iface, ethertype_arp);

        free(arp_hdr);

    }
    
}

void sr_send_arp_req(struct sr_instance *sr, uint32_t target_ip){
    char * iface = sr_get_iface_from_gw_ip(sr, target_ip);
    if(iface){
        uint8_t target[ETHER_ADDR_LEN];
        int i;
        for(i = 0; i < ETHER_ADDR_LEN; i++){
            target[i] = 255;
        }
        sr_send_arp(sr, arp_op_request, iface, (unsigned char*)target, target_ip); // not empty string?    
    }
    
}

void sr_send_arp_reply(struct sr_instance *sr, char *iface, unsigned char * target_eth_addr, uint32_t target_ip){
    sr_send_arp(sr, arp_op_reply, iface, target_eth_addr, target_ip);
}

/* Tries to find ip address in arp cache. If found, sends ethernet frame. If not found,
adds packet to arp queue */
void sr_attempt_send(struct sr_instance *sr, uint32_t ip_dest, 
                                        uint8_t *frame,           
                                       unsigned int frame_len,
                                       char *iface){
    //need to free entry!!
    //fprintf(stderr, "\n-----------------------------------IN ATTEMPT SEND----------------------\n");
   struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip_dest);

   if (entry){
        //fprintf(stderr, "Found cache entry for: \n");
        //print_addr_ip_int(ntohl(ip_dest));
        unsigned char *mac_address = entry->mac;
        memcpy( ((sr_ethernet_hdr_t *)frame)->ether_dhost, mac_address, ETHER_ADDR_LEN);
        //free packet??
        sr_send_packet(sr, frame, frame_len, iface);


        // Need to build ethernet header

        free(entry);


   }else{
        //fprintf(stderr, "Couldn't find entry for: ");
        //print_addr_ip_int(ntohl(ip_dest));
       // fprintf(stderr, " in cache....queueing entry\n");

       struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ip_dest, frame, frame_len, iface);
       sr_handle_arpreq(sr, req);
   }
}

int diff_time(time_t a, time_t b){
    //fprintf(stderr, "time a: %d\n", a);
    //fprintf(stderr, "time b: %d\n", b);
    return a-b;
}

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req){
    //fprintf(stderr, "\n-----------------------------------IN HANDLE ARP REQ----------------------\n");
    struct sr_arpcache *cache = &(sr->cache);
    time_t now = time(NULL);
    
    if(diff_time(now, req->sent) > 1.0){
        //fprintf(stderr, "handling arp req for ip: ");
        //print_addr_ip_int(ntohl(req->ip));
        if(req->times_sent >= 5){
            fprintf(stderr, "Sent 5 times, destroying..... \n");
            // Send an ICMP host unreachable to ALL packets waiting
            sr_arpreq_destroy(cache, req);
        }else{
            //send ARP
            //fprintf(stderr, "Sending ARP for %d time..... \n", req->times_sent + 1);
            sr_send_arp_req(sr, req->ip);
            req->sent = now;
            req->times_sent++;

        }
    }
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    struct sr_arpreq *req = sr->cache.requests;
    while(req){
        sr_handle_arpreq(sr, req);
        req = req->next;
    }
}

void sr_recv_arp(struct sr_instance *sr, struct sr_arp_hdr *arp){
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp->ar_sha, arp->ar_sip);
    if(req){
       // fprintf(stderr, "\nSending requests waiting to go to: \n");
        //print_addr_ip_int(ntohl(req->ip));
        struct sr_packet *packet = req->packets;
        while(packet){
           // fprintf(stderr, "\n------------------Sending this packet from queue----------------------\n");
            //print_hdrs(packet->buf, packet->len);
            sr_attempt_send(sr, req->ip, packet->buf, packet->len, packet->iface);
            //sr_send_packet(sr, packet->buf, packet->len, packet->iface);

            packet = packet->next;
        }

        sr_arpreq_destroy(&(sr->cache), req);

    }

}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        //printf("ip is: %u\n", cache->entries[i].ip);
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {

            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

void sr_print_queue(struct sr_arpcache *cache){
    fprintf(stderr, "------------------printing ARP Queue------------------\n");
    struct sr_arpreq *request = cache->requests;
    while(request){
        print_addr_ip_int(ntohl(request->ip));
        fprintf(stderr, "time sent: %d \t num times sent: %u \n", request->sent, request->times_sent);
        struct sr_packet *packet = request->packets;
        while(packet){
            fprintf(stderr, "len: %u \t outgoing interface: %s\n", packet->len, packet->iface);
            packet = packet->next;
        }
        fprintf(stderr, "\n");
        request = request->next;
    }
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}


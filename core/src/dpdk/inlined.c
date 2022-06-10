#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_ring.h>
#include <rte_cycles.h>

void rte_pktmbuf_free_(struct rte_mbuf *packet) {
    rte_pktmbuf_free(packet);
}

struct rte_mbuf* rte_pktmbuf_alloc_(struct rte_mempool *mp) {
    return rte_pktmbuf_alloc(mp);
}

uint16_t rte_eth_tx_burst_(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

uint16_t rte_eth_rx_burst_(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, const uint16_t nb_pkts) {
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t rte_mbuf_refcnt_read_(const struct rte_mbuf* m) {
    return rte_mbuf_refcnt_read(m);
}

uint16_t rte_mbuf_refcnt_update_(struct rte_mbuf* m, int16_t value) {
    return rte_mbuf_refcnt_update(m, value);
}

char* rte_pktmbuf_adj_(struct rte_mbuf* m, uint16_t len) {
    return rte_pktmbuf_adj(m, len);
}

int rte_pktmbuf_trim_(struct rte_mbuf* m, uint16_t len) {
    return rte_pktmbuf_trim(m, len);
}

unsigned rte_lcore_id_(void) {
    return rte_lcore_id();
}

uint64_t rte_rdtsc_(void) {
    return rte_rdtsc();
}

/* RTE_RING functions */

int rte_ring_enqueue_(struct rte_ring* r, void* obj) {
    return rte_ring_enqueue(r, obj);
}

int rte_ring_sp_enqueue_(struct rte_ring* r, void* obj) {
    return rte_ring_sp_enqueue(r, obj);
}

int rte_ring_mp_enqueue_(struct rte_ring* r, void* obj) {
    return rte_ring_mp_enqueue(r, obj);
}

int rte_ring_dequeue_(struct rte_ring* r, void** obj_p) {
    return rte_ring_dequeue(r, obj_p);
}

int rte_ring_sc_dequeue_(struct rte_ring* r, void** obj_p) {
    return rte_ring_sc_dequeue(r, obj_p);
}

int rte_ring_mc_dequeue_(struct rte_ring* r, void** obj_p) {
    return rte_ring_mc_dequeue(r, obj_p);
}

unsigned rte_ring_count_(const struct rte_ring* r) {
    return rte_ring_count(r);
}

unsigned rte_ring_free_count_(const struct rte_ring* r) {
    return rte_ring_free_count(r);
}

int rte_ring_full_(const struct rte_ring* r) {
    return rte_ring_full(r);
}

int rte_ring_empty_(const struct rte_ring* r) {
    return rte_ring_empty(r);
}

unsigned rte_ring_get_size_(const struct rte_ring* r) {
    return rte_ring_get_size(r);
}

unsigned rte_ring_get_capacity_(const struct rte_ring* r) {
    return rte_ring_get_capacity(r);
}

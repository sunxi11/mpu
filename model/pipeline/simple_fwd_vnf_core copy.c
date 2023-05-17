/*
 * Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>

#include <dpdk_utils.h>
#include <utils.h>

#include "simple_fwd_ft.h"
#include "simple_fwd_port.h"
#include "simple_fwd_vnf_core.h"
#include "cm.h"

DOCA_LOG_REGISTER(SIMPLE_FWD_VNF:Core);

#define VNF_PKT_L2(M) rte_pktmbuf_mtod(M, uint8_t *)	/* A marco that points to the start of the data in the mbuf */
#define VNF_PKT_LEN(M) rte_pktmbuf_pkt_len(M)		/* A marco that returns the length of the packet */
#define VNF_RX_BURST_SIZE (32)				/* Burst size of packets to read, RX burst read size */
//#define RTE_MAX_LCORE (7)

uint64_t num_packet = 0;
/* Flag for forcing lcores to stop processing packets, and gracefully terminate the application */
static volatile bool force_quit;
/* Parameters used by each core */
struct vnf_per_core_params {
	int ports[NUM_OF_PORTS];	/* Ports identifiers */
	int queues[NUM_OF_PORTS];	/* Queue mapped for the core running */
	bool used;			/* Whether the core is used or not */
};



/* per core parameters */
struct vnf_per_core_params core_params_arr[RTE_MAX_LCORE];

/*
 * Adjust the mbuf pointer, to point on the packet's raw data
 *
 * @m [in]: DPDK structure represent the packet received
 * @pinfo [in]: packet info representation  in the application
 */
static void
vnf_adjust_mbuf(struct rte_mbuf *m,
		struct simple_fwd_pkt_info *pinfo)
{
	int diff = pinfo->outer.l2 - VNF_PKT_L2(m);

	rte_pktmbuf_adj(m, diff);
}

/*
 * Process received packets, mainly retrieving packet's key, then checking if there is an entry found
 * matching the generated key, in the entries table.
 * If no entry found, the function will create and add new one.
 * In addition, this function handles aging as well
 *
 * @mbuf [in]: DPDK structure represent the packet received
 * @queue_id [in]: Queue ID
 * @vnf [in]: Holder for all functions pointers used by the application
 */
static void
simple_fwd_process_offload(struct rte_mbuf *mbuf, uint16_t queue_id, struct app_vnf *vnf, int seed)
{
	struct ipv4_5tuple *ft = (struct ipv4_5tuple *)malloc(sizeof(struct ipv4_5tuple));

	uint32_t sip, dip;
    uint16_t sp, dp;
    uint8_t proto_id;

	memset(ft, 0, sizeof(struct ipv4_5tuple));

	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	sip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	dip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	proto_id = ipv4_hdr->next_proto_id;

	struct rte_udp_hdr *udphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	sp = rte_be_to_cpu_16(udphdr->src_port);
	dp = rte_be_to_cpu_16(udphdr->dst_port);
	// // 给结构体赋值
	ft->ip_src = sip;
	ft->ip_dst = dip;
	ft->port_src = sp;
	ft->port_dst = dp;
	ft->proto = proto_id;

	uint32_t f = 1;
	for (int m = 0; m < M; ++m)
	{

		uint32_t index = murmur3((const void *)ft, sizeof(ft), seed) % N;
		uint32_t sign = murmur3((const void *)ft, sizeof(ft), seed) % 2;
		counters[m][index] += sign ? f : -f;

	}


	num_packet++;
	// if(num_packet % 10000 == 0){
	// 	printf("core %d get %"PRIu64"w packet\n",rte_lcore_id(), num_packet/10000);
	// }
	free(ft);
}
static void
simple_fwd_process_offload_core_0(struct rte_mbuf *mbuf, uint16_t queue_id, struct app_vnf *vnf, int seed){
	//todo 收包，解析出5元组，然后存放指针到5元组的数组中
	if(ft_index >= 0 && ft_index <= cache_size){
		struct ipv4_5tuple ft = {0};

		uint32_t sip, dip;
		uint16_t sp, dp;
		uint8_t proto_id;

		struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
		sip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		dip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		proto_id = ipv4_hdr->next_proto_id;

		struct rte_udp_hdr *udphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
		sp = rte_be_to_cpu_16(udphdr->src_port);
		dp = rte_be_to_cpu_16(udphdr->dst_port);
		// // 给结构体赋值
		ft.ip_src = sip;
		ft.ip_dst = dip;
		ft.port_src = sp;
		ft.port_dst = dp;
		ft.proto = proto_id;

		ft_cache[ft_index % cache_size] = ft;
		ft_index++;
	}


}

static void
simple_fwd_process_offload_core_1(){
	//todo 计算 hash  ft_index >= 0 && ft_index <= cache_size
	if(ft_index >= 0){
		struct ipv4_5tuple* ft = &ft_cache[ft_index % cache_size];
		if(hash_index >= 0 && hash_index <= cache_size){

			//struct ipv4_hash H = hash_cache[hash_index];
			struct ipv4_hash tem = {0};
			uint32_t seed = ft_index % 24;
			for (int m = 0; m < M; ++m)
			{

				uint32_t index = murmur3((const void *)ft, sizeof(ft), seed) % N;
				uint32_t sign = murmur3((const void *)ft, sizeof(ft), seed) % 2;
				tem.index[m] = index;
				tem.sign[m] = sign;
			}
			hash_cache[hash_index % cache_size] = tem;
			hash_index++;
		}

	}
	if(ft_index > 0){
		ft_index--;
	}



}


static void
simple_fwd_process_offload_core_2(){
	//todo update
	if(hash_index >= 0 && hash_index <= cache_size){
		uint32_t index, sign;
		struct ipv4_hash hash = hash_cache[hash_index % cache_size];

		uint32_t f = 1;
		for (int m = 0; m < M; ++m)
		{
			index = hash.index[m];
			sign = hash.sign[m];
			counters[m][index] += sign ? f : -f;
		}
		num_packet++;
		if(num_packet % 1000000 == 0){
			printf("core %d get %"PRIu64"00w packet\n",rte_lcore_id(), num_packet/1000000);
			printf("ft_index = %"PRIu32"\n", ft_index);
			printf("hash_index = %"PRIu32"\n", hash_index);
		}

	}

	if(hash_index > 0){
		hash_index--;
	}

}



int
simple_fwd_process_pkts(void *process_pkts_params)
{
	int result;
	uint64_t cur_tsc, last_tsc;
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t j, nb_rx, queue_id;
	uint32_t port_id = 0, core_id = rte_lcore_id();
	struct vnf_per_core_params *params = &core_params_arr[core_id];
	struct simple_fwd_config *app_config = ((struct simple_fwd_process_pkts_params *) process_pkts_params)->cfg;
	struct app_vnf *vnf = ((struct simple_fwd_process_pkts_params *) process_pkts_params)->vnf;

	printf("#########core id = %d#########\n", core_id);
	if (!params->used) {
		DOCA_LOG_DBG("core %u nothing need to do", core_id);
		return 0;
	}
	DOCA_DLOG_INFO("core %u process queue %u start", core_id, params->queues[0]);
	last_tsc = rte_rdtsc();
	while (!force_quit) {
		// if (core_id == rte_get_main_lcore()) {
		// 	cur_tsc = rte_rdtsc();
		// 	if (cur_tsc > last_tsc + app_config->stats_timer) {
		// 		result = vnf->vnf_dump_stats(0);
		// 		if (result != 0)
		// 			return result;
		// 		last_tsc = cur_tsc;
		// 	}
		// }
		for (port_id = 0; port_id < NUM_OF_PORTS; port_id++) {
			queue_id = params->queues[port_id];
			nb_rx = rte_eth_rx_burst(port_id, queue_id, mbufs, VNF_RX_BURST_SIZE);
			for (j = 0; j < nb_rx; j++) {
				if (app_config->hw_offload)
					simple_fwd_process_offload(mbufs[j], queue_id, vnf, j);
				//if (app_config->rx_only)
					rte_pktmbuf_free(mbufs[j]);
				//else
				//	rte_eth_tx_burst(port_id ^ 1, queue_id, &mbufs[j], 1);
			}
			// if (!app_config->age_thread)
			// 	vnf->vnf_flow_age(port_id, queue_id);
		}
	}
	return 0;
}

int
simple_fwd_process_pkts_pipe(void *process_pkts_params)
{
	int result;
	int operate;
	uint64_t cur_tsc, last_tsc;
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t j, nb_rx, queue_id;
	uint32_t port_id = 0, core_id = rte_lcore_id();
	struct vnf_per_core_params *params = &core_params_arr[core_id];
	struct simple_fwd_config *app_config = ((struct simple_fwd_process_pkts_params *) process_pkts_params)->cfg;
	struct app_vnf *vnf = ((struct simple_fwd_process_pkts_params *) process_pkts_params)->vnf;

	// printf("#########core id = %d#########\n", core_id);
	if (!params->used) {
		DOCA_LOG_DBG("core %u nothing need to do", core_id);
		return 0;
	}
	printf("core %u process queue %u start\n", core_id, params->queues[0]);

	if(core_id == 0)
		operate = 0;
	
	if(core_id == 1 || core_id == 2 || core_id == 4 || core_id == 5 || core_id == 6 || core_id == 3)
		operate = 1;

	if(core_id == 7)
		operate = 2;

	switch (operate) {
		case 0:{
			while (!force_quit) {
				for (port_id = 0; port_id < NUM_OF_PORTS; port_id++) {
					queue_id = params->queues[port_id];
					nb_rx = rte_eth_rx_burst(port_id, queue_id, mbufs, VNF_RX_BURST_SIZE);
					for (j = 0; j < nb_rx; j++) {
						if (app_config->hw_offload)
							simple_fwd_process_offload_core_0(mbufs[j], queue_id, vnf, j);
							rte_pktmbuf_free(mbufs[j]);
					}
				}
			}
			break;
		}
		case 1:{
			while(!force_quit){
				simple_fwd_process_offload_core_1();
			}
			break;
		}

		case 2:{
			while(!force_quit){
				simple_fwd_process_offload_core_2();
			}
			break;
		}
		default:
			printf("Invalid condition\n");
			break;
	}
	
	

	return 0;
}






void
simple_fwd_process_pkts_stop()
{
	force_quit = true;
}

/*
 * Callback function for setting time stats dump
 *
 * @param [in]: time for dumping stats
 * @config [out]: application configuration for setting the time
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
stats_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *) config;

	app_config->stats_timer = *(int *) param;
	DOCA_LOG_DBG("set stats_timer:%lu", app_config->stats_timer);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting number of queues
 *
 * @param [in]: number of queues to set
 * @config [out]: application configuration for setting the number of queues
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
nr_queues_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *) config;
	int nr_queues = *(int *) param;

	if (nr_queues < 2) {
		DOCA_LOG_ERR("Invalid nr_queues should >= 2");
		return DOCA_ERROR_INVALID_VALUE;
	}
	app_config->dpdk_cfg->port_config.nb_queues = nr_queues;
	app_config->dpdk_cfg->port_config.rss_support = 1;
	DOCA_LOG_DBG("set nr_queues:%u", nr_queues);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting the "rx-only" mode, where the application only receives packets
 *
 * @param [in]: parameter indicates whther or not to set the "rx-only" mode
 * @config [out]: application configuration to set the "rx-only" mode
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rx_only_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *) config;

	app_config->rx_only = *(bool *) param ? 1 : 0;
	DOCA_LOG_DBG("set rx_only:%u", app_config->rx_only);
	return DOCA_SUCCESS;
}

/*
 * Callback function for the HW offload
 *
 * @param [in]: parameter indicates whther or not to set the HW offload
 * @config [out]: application configuration to set the HW offload
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
hw_offload_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *) config;

	app_config->hw_offload = *(bool *) param ? 1 : 0;
	DOCA_LOG_DBG("set hw_offload:%u", app_config->hw_offload);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting the haiprin usage
 *
 * @param [in]: parameter indicates whther or not to use hairpin queues
 * @config [out]: application configuration to set hairpin usage
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
hairpinq_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *) config;

	app_config->dpdk_cfg->port_config.nb_hairpin_q = *(bool *) param ? 1 : 0;
	DOCA_LOG_DBG("set is_hairpin:%u", app_config->dpdk_cfg->port_config.nb_hairpin_q);
	return DOCA_SUCCESS;
}

/*
 * Callback function for setting dedicated thread for aging handling
 *
 * @param [in]: parameter indicates whther or not to use dedicated thread for aging
 * @config [out]: application configuration to set the usage of a dedicated thread for aged flows
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
age_thread_callback(void *param, void *config)
{
	struct simple_fwd_config *app_config = (struct simple_fwd_config *) config;

	app_config->age_thread = *(bool *) param;
	DOCA_LOG_DBG("set age_thread:%s", app_config->age_thread ? "true":"false");
	return DOCA_SUCCESS;
}

/*
 * Registers all flags used by the application for DOCA argument parser, so that when parsing
 * it can be parsed accordingly
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
register_simple_fwd_params()
{
	doca_error_t result;
	struct doca_argp_param *stats_param, *nr_queues_param, *rx_only_param, *hw_offload_param;
	struct doca_argp_param *hairpinq_param, *age_thread_param;

	/* Create and register stats timer param */
	result = doca_argp_param_create(&stats_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(stats_param, "t");
	doca_argp_param_set_long_name(stats_param, "stats-timer");
	doca_argp_param_set_arguments(stats_param, "<time>");
	doca_argp_param_set_description(stats_param, "Set interval to dump stats information");
	doca_argp_param_set_callback(stats_param, stats_callback);
	doca_argp_param_set_type(stats_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(stats_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register queues number param */
	result = doca_argp_param_create(&nr_queues_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(nr_queues_param, "q");
	doca_argp_param_set_long_name(nr_queues_param, "nr-queues");
	doca_argp_param_set_arguments(nr_queues_param, "<num>");
	doca_argp_param_set_description(nr_queues_param, "Set queues number");
	doca_argp_param_set_callback(nr_queues_param, nr_queues_callback);
	doca_argp_param_set_type(nr_queues_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(nr_queues_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register RX only param */
	result = doca_argp_param_create(&rx_only_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rx_only_param, "r");
	doca_argp_param_set_long_name(rx_only_param, "rx-only");
	doca_argp_param_set_description(rx_only_param, "Set rx only");
	doca_argp_param_set_callback(rx_only_param, rx_only_callback);
	doca_argp_param_set_type(rx_only_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(rx_only_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register HW offload param */
	result = doca_argp_param_create(&hw_offload_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(hw_offload_param, "o");
	doca_argp_param_set_long_name(hw_offload_param, "hw-offload");
	doca_argp_param_set_description(hw_offload_param, "Set PCI address of the RXP engine to use");
	doca_argp_param_set_callback(hw_offload_param, hw_offload_callback);
	doca_argp_param_set_type(hw_offload_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(hw_offload_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register hairpin queue param */
	result = doca_argp_param_create(&hairpinq_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(hairpinq_param, "hq");
	doca_argp_param_set_long_name(hairpinq_param, "hairpinq");
	doca_argp_param_set_description(hairpinq_param, "Set forwarding to hairpin queue");
	doca_argp_param_set_callback(hairpinq_param, hairpinq_callback);
	doca_argp_param_set_type(hairpinq_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(hairpinq_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register age thread param */
	result = doca_argp_param_create(&age_thread_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(age_thread_param, "a");
	doca_argp_param_set_long_name(age_thread_param, "age-thread");
	doca_argp_param_set_description(age_thread_param, "Start thread do aging");
	doca_argp_param_set_callback(age_thread_param, age_thread_callback);
	doca_argp_param_set_type(age_thread_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(age_thread_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Register version callback for DOCA SDK & RUNTIME */
	result = doca_argp_register_version_callback(sdk_version_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register version callback: %s", doca_get_error_string(result));
		return result;
	}
	return DOCA_SUCCESS;
}

void
simple_fwd_map_queue(uint16_t nb_queues)
{
	int i, queue_idx = 0;

	memset(core_params_arr, 0, sizeof(core_params_arr));
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled(i))
			continue;
		core_params_arr[i].ports[0] = 0;
		core_params_arr[i].ports[1] = 1;
		core_params_arr[i].queues[0] = queue_idx;
		core_params_arr[i].queues[1] = queue_idx;
		core_params_arr[i].used = true;
		queue_idx++;
		if (queue_idx >= nb_queues)
			break;
	}
}

void
simple_fwd_map_queue_pipe(uint16_t nb_queues)
{
	int i, queue_idx = 0;

	memset(core_params_arr, 0, sizeof(core_params_arr));
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_is_enabled(i))
			continue;
		if(i == 0 || i == 3){
			core_params_arr[i].ports[0] = 0;
			core_params_arr[i].ports[1] = 1;
			core_params_arr[i].queues[0] = queue_idx;
			core_params_arr[i].queues[1] = queue_idx;
			
			queue_idx++;
		}
		core_params_arr[i].used = true;
		if (queue_idx >= nb_queues)
			break;
	}
}


void
simple_fwd_destroy(struct app_vnf *vnf)
{
	vnf->vnf_destroy();
}

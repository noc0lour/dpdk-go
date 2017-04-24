package dpdk

/*
#cgo CFLAGS: -m64 -pthread -O3 -march=native -I/usr/local/include/dpdk
#cgo LDFLAGS: -L/usr/local/lib -ldpdk -lz -lrt -lm -ldl -lfuse

#include <rte_config.h>
#include <rte_ethdev.h>
#include <wrap.h>

const uint8_t SYMMETRICAL_HASH_KEY[] = {0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A};
const uint8_t SIMPLE_SYMMETRICAL_HASH_KEY[] = {0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01};

static int update_rss_flow(uint8_t port_id, uint32_t flow_type, uint32_t flow_field, enum rte_filter_input_set_op operation)
{
	struct rte_eth_hash_filter_info info;
	memset(&info, 0, sizeof(info));

	info.info_type = RTE_ETH_HASH_FILTER_INPUT_SET_SELECT;
	info.info.input_set_conf.flow_type = flow_type;
	info.info.input_set_conf.field[0] = flow_field;
	info.info.input_set_conf.inset_size = 1;

	info.info.input_set_conf.op = operation;
	int result = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);

	return result;
}

static int enable_symmetrical_rss_hash_for_flow(uint8_t port_id, uint32_t flow_type)
{
	if (rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_HASH) < 0) {
		return -1000;
	}

	struct rte_eth_hash_filter_info info;
	memset(&info, 0, sizeof(info));

	info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
	info.info.global_conf.hash_func = RTE_ETH_HASH_FUNCTION_DEFAULT;

	uint32_t idx, offset;

	idx = flow_type / (CHAR_BIT * sizeof(uint32_t));
	offset = flow_type % (CHAR_BIT * sizeof(uint32_t));
	info.info.global_conf.valid_bit_mask[idx] |= (1UL << offset);

	// enable
	info.info.global_conf.sym_hash_enable_mask[idx] |= (1UL << offset);

	int result = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);

	return result;
}


static int enable_symmetrical_rss_hash_for_port(uint8_t port_id)
{
	if (rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_HASH) < 0) {
		return -1000;
	}

	struct rte_eth_hash_filter_info info;
	memset(&info, 0, sizeof(info));

	info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;
	info.info.enable = 1;

	int result = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);

	return result;
}

*/
import "C"

import (
	"fmt"
	"math"
	"unsafe"
)

/* Macros */
const (
	ETH_LINK_SPEED_AUTONEG          = int(C.ETH_LINK_SPEED_AUTONEG)
	ETH_LINK_SPEED_10M_HD           = int(C.ETH_LINK_SPEED_10M_HD)
	ETH_LINK_SPEED_10M              = int(C.ETH_LINK_SPEED_10M)
	ETH_LINK_SPEED_100M_HD          = int(C.ETH_LINK_SPEED_100M_HD)
	ETH_LINK_SPEED_100M             = int(C.ETH_LINK_SPEED_100M)
	ETH_LINK_SPEED_1G               = int(C.ETH_LINK_SPEED_1G)
	ETH_LINK_SPEED_2_5G             = int(C.ETH_LINK_SPEED_2_5G)
	ETH_LINK_SPEED_5G               = int(C.ETH_LINK_SPEED_5G)
	ETH_LINK_SPEED_10G              = int(C.ETH_LINK_SPEED_10G)
	ETH_LINK_SPEED_20G              = int(C.ETH_LINK_SPEED_20G)
	ETH_LINK_SPEED_25G              = int(C.ETH_LINK_SPEED_25G)
	ETH_LINK_SPEED_40G              = int(C.ETH_LINK_SPEED_40G)
	ETH_LINK_SPEED_50G              = int(C.ETH_LINK_SPEED_50G)
	ETH_LINK_SPEED_56G              = int(C.ETH_LINK_SPEED_56G)
	ETH_LINK_SPEED_100G             = int(C.ETH_LINK_SPEED_100G)
	ETH_LINK_HALF_DUPLEX            = int(C.ETH_LINK_HALF_DUPLEX)
	ETH_LINK_FULL_DUPLEX            = int(C.ETH_LINK_FULL_DUPLEX)
	ETH_MQ_RX_RSS_FLAG              = int(C.ETH_MQ_RX_RSS_FLAG)
	ETH_RSS                         = int(C.ETH_RSS)
	ETH_DCB_NONE                    = int(C.ETH_DCB_NONE)
	ETH_RSS_SCTP                    = int(C.ETH_RSS_SCTP)
	ETH_VMDQ_MAX_VLAN_FILTERS       = int(C.ETH_VMDQ_MAX_VLAN_FILTERS)
	ETH_DCB_NUM_USER_PRIORITIES     = int(C.ETH_DCB_NUM_USER_PRIORITIES)
	ETH_VMDQ_DCB_NUM_QUEUES         = int(C.ETH_VMDQ_DCB_NUM_QUEUES)
	ETH_DCB_NUM_QUEUES              = int(C.ETH_DCB_NUM_QUEUES)
	ETH_DCB_PG_SUPPORT              = int(C.ETH_DCB_PG_SUPPORT)
	ETH_DCB_PFC_SUPPORT             = int(C.ETH_DCB_PFC_SUPPORT)
	ETH_VLAN_STRIP_OFFLOAD          = int(C.ETH_VLAN_STRIP_OFFLOAD)
	ETH_VLAN_FILTER_OFFLOAD         = int(C.ETH_VLAN_FILTER_OFFLOAD)
	ETH_VLAN_EXTEND_OFFLOAD         = int(C.ETH_VLAN_EXTEND_OFFLOAD)
	ETH_VLAN_STRIP_MASK             = int(C.ETH_VLAN_STRIP_MASK)
	ETH_VLAN_FILTER_MASK            = int(C.ETH_VLAN_FILTER_MASK)
	ETH_VLAN_EXTEND_MASK            = int(C.ETH_VLAN_EXTEND_MASK)
	ETH_VLAN_ID_MAX                 = int(C.ETH_VLAN_ID_MAX)
	ETH_NUM_RECEIVE_MAC_ADDR        = int(C.ETH_NUM_RECEIVE_MAC_ADDR)
	ETH_VMDQ_NUM_UC_HASH_ARRAY      = int(C.ETH_VMDQ_NUM_UC_HASH_ARRAY)
	ETH_VMDQ_ACCEPT_UNTAG           = int(C.ETH_VMDQ_ACCEPT_UNTAG)
	ETH_VMDQ_ACCEPT_HASH_MC         = int(C.ETH_VMDQ_ACCEPT_HASH_MC)
	ETH_VMDQ_ACCEPT_HASH_UC         = int(C.ETH_VMDQ_ACCEPT_HASH_UC)
	ETH_VMDQ_ACCEPT_BROADCAST       = int(C.ETH_VMDQ_ACCEPT_BROADCAST)
	ETH_VMDQ_ACCEPT_MULTICAST       = int(C.ETH_VMDQ_ACCEPT_MULTICAST)
	ETH_MIRROR_MAX_VLANS            = int(C.ETH_MIRROR_MAX_VLANS)
	ETH_MIRROR_VIRTUAL_POOL_UP      = int(C.ETH_MIRROR_VIRTUAL_POOL_UP)
	ETH_MIRROR_UPLINK_PORT          = int(C.ETH_MIRROR_UPLINK_PORT)
	ETH_MIRROR_DOWNLINK_PORT        = int(C.ETH_MIRROR_DOWNLINK_PORT)
	ETH_MIRROR_VLAN                 = int(C.ETH_MIRROR_VLAN)
	ETH_MIRROR_VIRTUAL_POOL_DOWN    = int(C.ETH_MIRROR_VIRTUAL_POOL_DOWN)
	ETH_TXQ_FLAGS_NOMULTSEGS        = int(C.ETH_TXQ_FLAGS_NOMULTSEGS)
	ETH_TXQ_FLAGS_NOREFCOUNT        = int(C.ETH_TXQ_FLAGS_NOREFCOUNT)
	ETH_TXQ_FLAGS_NOMULTMEMP        = int(C.ETH_TXQ_FLAGS_NOMULTMEMP)
	ETH_TXQ_FLAGS_NOVLANOFFL        = int(C.ETH_TXQ_FLAGS_NOVLANOFFL)
	ETH_TXQ_FLAGS_NOXSUMSCTP        = int(C.ETH_TXQ_FLAGS_NOXSUMSCTP)
	ETH_TXQ_FLAGS_NOXSUMUDP         = int(C.ETH_TXQ_FLAGS_NOXSUMUDP)
	ETH_TXQ_FLAGS_NOXSUMTCP         = int(C.ETH_TXQ_FLAGS_NOXSUMTCP)
	DEV_RX_OFFLOAD_VLAN_STRIP       = int(C.DEV_RX_OFFLOAD_VLAN_STRIP)
	DEV_TX_OFFLOAD_VLAN_INSERT      = int(C.DEV_TX_OFFLOAD_VLAN_INSERT)
	DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM = int(C.DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM)
	RTE_ETH_XSTATS_NAME_SIZE        = int(C.RTE_ETH_XSTATS_NAME_SIZE)
	RTE_ETH_QUEUE_STATE_STOPPED     = int(C.RTE_ETH_QUEUE_STATE_STOPPED)
	RTE_ETH_DEV_DETACHABLE          = int(C.RTE_ETH_DEV_DETACHABLE)
	RTE_ETH_DEV_INTR_LSC            = int(C.RTE_ETH_DEV_INTR_LSC)
)

/* enum rte_eth_rx_mq_mode */
const (
	ETH_MQ_RX_NONE         = int(C.ETH_MQ_RX_NONE)
	ETH_MQ_RX_RSS          = int(C.ETH_MQ_RX_RSS)
	ETH_MQ_RX_DCB          = int(C.ETH_MQ_RX_DCB)
	ETH_MQ_RX_DCB_RSS      = int(C.ETH_MQ_RX_DCB_RSS)
	ETH_MQ_RX_VMDQ_ONLY    = int(C.ETH_MQ_RX_VMDQ_ONLY)
	ETH_MQ_RX_VMDQ_RSS     = int(C.ETH_MQ_RX_VMDQ_RSS)
	ETH_MQ_RX_VMDQ_DCB     = int(C.ETH_MQ_RX_VMDQ_DCB)
	ETH_MQ_RX_VMDQ_DCB_RSS = int(C.ETH_MQ_RX_VMDQ_DCB_RSS)
)

/* enum rte_eth_tx_mq_mode */
const (
	ETH_MQ_TX_NONE      = int(C.ETH_MQ_TX_NONE)
	ETH_MQ_TX_DCB       = int(C.ETH_MQ_TX_DCB)
	ETH_MQ_TX_VMDQ_DCB  = int(C.ETH_MQ_TX_VMDQ_DCB)
	ETH_MQ_TX_VMDQ_ONLY = int(C.ETH_MQ_TX_VMDQ_ONLY)
)

/* enum rte_eth_nb_tcs */
const (
	ETH_4_TCS = int(C.ETH_4_TCS)
	ETH_8_TCS = int(C.ETH_8_TCS)
)

/* enum rte_eth_nb_pools */
const (
	ETH_8_POOLS  = int(C.ETH_8_POOLS)
	ETH_16_POOLS = int(C.ETH_16_POOLS)
	ETH_32_POOLS = int(C.ETH_32_POOLS)
	ETH_64_POOLS = int(C.ETH_64_POOLS)
)

/* enum rte_eth_fc_mode */
const (
	RTE_FC_NONE     = int(C.RTE_FC_NONE)
	RTE_FC_RX_PAUSE = int(C.RTE_FC_RX_PAUSE)
	RTE_FC_TX_PAUSE = int(C.RTE_FC_TX_PAUSE)
	RTE_FC_FULL     = int(C.RTE_FC_FULL)
)

/* enum rte_fdir_pballoc_type */
const (
	RTE_FDIR_PBALLOC_64K  = int(C.RTE_FDIR_PBALLOC_64K)
	RTE_FDIR_PBALLOC_128K = int(C.RTE_FDIR_PBALLOC_128K)
	RTE_FDIR_PBALLOC_256K = int(C.RTE_FDIR_PBALLOC_256K)
)

/* enum rte_fdir_status_mode */
const (
	RTE_FDIR_NO_REPORT_STATUS     = int(C.RTE_FDIR_NO_REPORT_STATUS)
	RTE_FDIR_REPORT_STATUS        = int(C.RTE_FDIR_REPORT_STATUS)
	RTE_FDIR_REPORT_STATUS_ALWAYS = int(C.RTE_FDIR_REPORT_STATUS_ALWAYS)
)

/* enum rte_eth_dev_type */
const (
	RTE_ETH_DEV_UNKNOWN = int(C.RTE_ETH_DEV_UNKNOWN)
	RTE_ETH_DEV_PCI     = int(C.RTE_ETH_DEV_PCI)
	RTE_ETH_DEV_VIRTUAL = int(C.RTE_ETH_DEV_VIRTUAL)
	RTE_ETH_DEV_MAX     = int(C.RTE_ETH_DEV_MAX)
)

/* enum rte_eth_event_type */
const (
	RTE_ETH_EVENT_UNKNOWN  = int(C.RTE_ETH_EVENT_UNKNOWN)
	RTE_ETH_EVENT_INTR_LSC = int(C.RTE_ETH_EVENT_INTR_LSC)
	RTE_ETH_EVENT_MAX      = int(C.RTE_ETH_EVENT_MAX)
)

type RteEthLink C.struct_rte_eth_link
type RteEthThresh C.struct_rte_eth_thresh
type RteEthRxMode C.struct_rte_eth_rxmode
type RteEthRssConf C.struct_rte_eth_rss_conf
type RteEthVlanMirror C.struct_rte_eth_vlan_mirror
type RteEthMirrorConf C.struct_rte_eth_mirror_conf
type RteEthRssRetaEntry64 C.struct_rte_eth_rss_reta_entry64
type RteEthVmdqDcbConf C.struct_rte_eth_vmdq_dcb_conf
type RteEthTxmode C.struct_rte_eth_txmode
type RteEthRxConf C.struct_rte_eth_rxconf
type RteEthTxConf C.struct_rte_eth_txconf
type RteEthDescLim C.struct_rte_eth_desc_lim
type RteEthFcConf C.struct_rte_eth_fc_conf
type RteEthPfcConf C.struct_rte_eth_pfc_conf
type RteFdirConf C.struct_rte_fdir_conf
type RteEthUdpTunnel C.struct_rte_eth_udp_tunnel
type RteIntrConf C.struct_rte_intr_conf
type RteEthConf C.struct_rte_eth_conf
type RteEthRxqInfo C.struct_rte_eth_rxq_info
type RteEthTxqInfo C.struct_rte_eth_txq_info
type RteEthXStats C.struct_rte_eth_xstats
type RteEthDcbTcQueueMapping C.struct_rte_eth_dcb_tc_queue_mapping
type RteEthDcbInfo C.struct_rte_eth_dcb_info
type RteEthAddr C.struct_ether_addr

type RteEthStats struct {
	PacketsReceived          uint64
	PacketsTransmitted       uint64
	BytesReceived            uint64
	BytesTransmitted         uint64
	PacketsMissedByQueue     uint64
	PacketsReceivedErroneous uint64
	PacketsTrasmitErrors     uint64
	MbufAllocationFailures   uint64
}

func RteEthDevCount() uint {
	return uint(C.rte_eth_dev_count())
}

func RteEthDevAttach(devargs string, port_id *uint) int {
	return int(C.rte_eth_dev_attach(C.CString(devargs),
		(*C.uint8_t)(unsafe.Pointer((port_id)))))
}

func RteEthDevDetach(port_id uint, devname string) int {
	return int(C.rte_eth_dev_detach(C.uint8_t(port_id), C.CString(devname)))
}

func RteEthDevConfigure(port_id, nb_rx_queue, nb_tx_queue uint, eth_conf *RteEthConf) int {
	return int(C.rte_eth_dev_configure(C.uint8_t(port_id),
		C.uint16_t(nb_rx_queue), C.uint16_t(nb_tx_queue),
		(*C.struct_rte_eth_conf)(eth_conf)))
}

func RteEthRxQueueSetup(port_id, rx_queue_id, nb_rx_desc, socket_id uint,
	rx_conf *RteEthRxConf, mb_pool *RteMemPool) int {
	return int(C.rte_eth_rx_queue_setup(C.uint8_t(port_id),
		C.uint16_t(rx_queue_id), C.uint16_t(nb_rx_desc),
		C.unsigned(socket_id), (*C.struct_rte_eth_rxconf)(rx_conf),
		(*C.struct_rte_mempool)(mb_pool)))
}

func RteEthTxQueueSetup(port_id, tx_queue_id, nb_tx_desc, socket_id uint,
	tx_conf *RteEthTxConf) int {
	return int(C.rte_eth_tx_queue_setup(C.uint8_t(port_id),
		C.uint16_t(tx_queue_id), C.uint16_t(nb_tx_desc),
		C.unsigned(socket_id), (*C.struct_rte_eth_txconf)(tx_conf)))
}

func RteEthDevStart(port_id uint) int {
	return int(C.rte_eth_dev_start(C.uint8_t(port_id)))
}

func RteEthDevStop(port_id uint) {
	C.rte_eth_dev_stop(C.uint8_t(port_id))
}

func RteEthDevSetLinkUp(port_id uint) int {
	return int(C.rte_eth_dev_set_link_up(C.uint8_t(port_id)))
}

func RteEthDevSetLinkDown(port_id uint) int {
	return int(C.rte_eth_dev_set_link_down(C.uint8_t(port_id)))
}

func RteEthDevClose(port_id uint) {
	C.rte_eth_dev_close(C.uint8_t(C.uint8_t(port_id)))
}

func RteEthPromiscuousEnable(port_id uint) {
	C.rte_eth_promiscuous_enable(C.uint8_t(port_id))
}

func RteEthPromiscuousDisable(port_id uint) {
	C.rte_eth_promiscuous_disable(C.uint8_t(port_id))
}

func RteEthPromiscuousGet(port_id uint) int {
	return int(C.rte_eth_promiscuous_get(C.uint8_t(port_id)))
}

func RteEthRxBurst(port_id, queue_id uint, rx_pkts *unsafe.Pointer, nb_pkts uint) uint {
	return uint(C.rte_eth_rx_burst(C.uint8_t(port_id), C.uint16_t(queue_id),
		(**C.struct_rte_mbuf)(unsafe.Pointer(rx_pkts)), C.uint16_t(nb_pkts)))
}

func RteEthRxQueueCount(port_id, queue_id uint) uint {
	return uint(C.rte_eth_rx_queue_count(C.uint8_t(port_id),
		C.uint16_t(queue_id)))
}

func RteEthRxQueueDescriptorDone(port_id, queue_id, offset uint) uint {
	return uint(C.rte_eth_rx_descriptor_done(C.uint8_t(port_id),
		C.uint16_t(queue_id), C.uint16_t(offset)))
}

func RteEthTxBurst(port_id, queue_id uint, tx_pkts *unsafe.Pointer, nb_pkts uint) uint {
	return uint(C.rte_eth_tx_burst(C.uint8_t(port_id), C.uint16_t(queue_id),
		(**C.struct_rte_mbuf)(unsafe.Pointer(tx_pkts)), C.uint16_t(nb_pkts)))
}

func RteEthDevSocketID(port_id uint) uint {
	return uint(C.rte_eth_dev_socket_id(C.uint8_t(port_id)))
}

func RteEthMacAddr(port_id uint) string {
	var addr C.struct_ether_addr
	C.rte_eth_macaddr_get(C.uint8_t(port_id), &addr)
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])
}

func RteEthRssFlowByIP() *RteEthConf {
	eth_conf := &RteEthConf{}

	conf := (*C.struct_rte_eth_conf)(unsafe.Pointer(eth_conf))
	conf.rxmode.mq_mode = C.ETH_MQ_RX_RSS
	conf.rx_adv_conf.rss_conf.rss_hf = C.ETH_RSS_TCP
	conf.rx_adv_conf.rss_conf.rss_key = (*C.uint8_t)(&C.SYMMETRICAL_HASH_KEY[0])

	return eth_conf
}

func RteEthSetRssFlowByTCP(port_id uint) int {
	conf := &C.struct_rte_eth_rss_conf{}

	conf.rss_hf = C.ETH_RSS_NONFRAG_IPV4_TCP
	conf.rss_key = (*C.uint8_t)(&C.SYMMETRICAL_HASH_KEY[0])

	result := C.rte_eth_dev_rss_hash_update(C.uint8_t(port_id), conf)
	return int(result)
}

func RteEthSetRssFlowByTCPForIntel710(port_id uint) int {
	if res := RteEthSetRssFlowByTCP(port_id); res < 0 {
		return int(res)
	}

	if res := C.update_rss_flow(C.uint8_t(port_id), C.RTE_ETH_FLOW_NONFRAG_IPV4_TCP, C.RTE_ETH_INPUT_SET_L3_SRC_IP4, C.RTE_ETH_INPUT_SET_SELECT); res < 0 {
		return int(res)
	}

	if res := C.update_rss_flow(C.uint8_t(port_id), C.RTE_ETH_FLOW_NONFRAG_IPV4_TCP, C.RTE_ETH_INPUT_SET_L3_DST_IP4, C.RTE_ETH_INPUT_SET_ADD); res < 0 {
		return int(res)
	}

	if res := C.update_rss_flow(C.uint8_t(port_id), C.RTE_ETH_FLOW_FRAG_IPV4, C.RTE_ETH_INPUT_SET_L3_SRC_IP4, C.RTE_ETH_INPUT_SET_SELECT); res < 0 {
		return int(res)
	}

	if res := C.update_rss_flow(C.uint8_t(port_id), C.RTE_ETH_FLOW_FRAG_IPV4, C.RTE_ETH_INPUT_SET_L3_DST_IP4, C.RTE_ETH_INPUT_SET_ADD); res < 0 {
		return int(res)
	}

	if res := C.enable_symmetrical_rss_hash_for_port(C.uint8_t(port_id)); res < 0 {
		return int(res)
	}

	if res := C.enable_symmetrical_rss_hash_for_flow(C.uint8_t(port_id), C.RTE_ETH_FLOW_NONFRAG_IPV4_TCP); res < 0 {
		return int(res)
	}

	if res := C.enable_symmetrical_rss_hash_for_flow(C.uint8_t(port_id), C.RTE_ETH_FLOW_FRAG_IPV4); res < 0 {
		return int(res)
	}

	if res := C.enable_symmetrical_rss_hash_for_flow(C.uint8_t(port_id), C.RTE_ETH_FLOW_NONFRAG_IPV4_OTHER); res < 0 {
		return int(res)
	}

	return 0
}

func RteEthInitRetaTable(port_id uint, queues_count uint) int {
	var dev_info C.struct_rte_eth_dev_info
	C.rte_eth_dev_info_get(C.uint8_t(port_id), &dev_info)

	var reta_conf [512]C.struct_rte_eth_rss_reta_entry64

	for group := 0; group < int(dev_info.reta_size); group++ {
		reta_conf[group/C.RTE_RETA_GROUP_SIZE].mask = C.uint64_t(math.MaxUint64)

		for i := uint(0); i < C.RTE_RETA_GROUP_SIZE; i += queues_count {
			for q := uint(0); q < queues_count && i+q < C.RTE_RETA_GROUP_SIZE; q++ {
				reta_conf[group/C.RTE_RETA_GROUP_SIZE].reta[i+q] = C.uint16_t(q)
			}
		}
	}

	result := C.rte_eth_dev_rss_reta_update(
		C.uint8_t(port_id),
		(*C.struct_rte_eth_rss_reta_entry64)(unsafe.Pointer(&reta_conf[0])),
		dev_info.reta_size,
	)

	return int(result)
}

func RteEthGetStats(port_id uint) RteEthStats {
	cstats := C.struct_rte_eth_stats{}
	C.rte_eth_stats_get(C.uint8_t(port_id), &cstats)

	stats := RteEthStats{
		PacketsReceived:          uint64(cstats.ipackets),
		PacketsTransmitted:       uint64(cstats.opackets),
		BytesReceived:            uint64(cstats.ibytes),
		BytesTransmitted:         uint64(cstats.obytes),
		PacketsMissedByQueue:     uint64(cstats.imissed),
		PacketsReceivedErroneous: uint64(cstats.ierrors),
		PacketsTrasmitErrors:     uint64(cstats.oerrors),
		MbufAllocationFailures:   uint64(cstats.rx_nombuf),
	}

	return stats
}

func RteEthClearStats(port_id uint) {
	C.rte_eth_stats_reset(C.uint8_t(port_id))
}

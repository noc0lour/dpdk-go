package dpdk

/*
#cgo CFLAGS: -m64 -pthread -O3 -march=native -I/usr/local/include/dpdk
#cgo LDFLAGS: -Wl,--as-needed -L/usr/local/lib -ldpdk -lz -lrt -lm -ldl -lfuse -lpcap

#include <stdint.h>
#include <rte_pdump.h>
*/
import "C"

func RtePdumpInit() int {
	return int(C.rte_pdump_init(nil))
}

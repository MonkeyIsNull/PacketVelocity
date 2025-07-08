/* Linux NUMA-aware Capture Demo
 * Demonstrates NUMA optimization and CPU pinning on Linux
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __linux__
#include "pcv_xdp_linux.h"

void demonstrate_numa_features(const char* interface) {
    int numa_node;
    int ifindex;
    
    printf("Linux AF_XDP NUMA Demo\n");
    printf("======================\n");
    
    /* Get interface index */
    ifindex = pcv_xdp_get_ifindex(interface);
    printf("Interface %s has index: %d\n", interface, ifindex);
    
    /* Get NUMA node for interface */
    numa_node = pcv_xdp_get_numa_node(interface);
    if (numa_node >= 0) {
        printf("Interface %s is on NUMA node: %d\n", interface, numa_node);
    } else {
        printf("Interface %s NUMA node: unknown\n", interface);
    }
    
    /* Demonstrate CPU affinity setting */
    printf("Setting CPU affinity to core 0...\n");
    pcv_xdp_set_cpu_affinity(0);
    
    /* Demonstrate NUMA-aware memory allocation */
    printf("Allocating NUMA-aware memory...\n");
    void* numa_mem = pcv_xdp_alloc_numa(4096, numa_node);
    if (numa_mem) {
        printf("Successfully allocated 4KB on NUMA node %d\n", numa_node);
        free(numa_mem);
    }
    
    /* Demonstrate XDP modes */
    printf("\nXDP Program Management:\n");
    printf("Setting XDP program in native mode...\n");
    pcv_xdp_set_prog(ifindex, PCV_XDP_MODE_DRV);
    
    printf("Removing XDP program...\n");
    pcv_xdp_remove_prog(ifindex);
}

int main(int argc, char* argv[]) {
    const char* interface = "eth0";  /* Default Linux interface */
    
    if (argc > 1) {
        interface = argv[1];
    }
    
    demonstrate_numa_features(interface);
    
    return 0;
}

#else

int main(void) {
    printf("This demo is only available on Linux.\n");
    return 0;
}

#endif
#include "ndpi_api.h"
#include <pcap/pcap.h>

#define BUF_SIZE 256
#define TICK_RESOLUTION 1000

// #define VERBOSE 0

struct nDPI_workflow {
    pcap_t * pcap_handle;

    uint8_t error_or_eof:1;
    uint8_t reserved_00:7;
    uint8_t reserved_01[3];

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_l4_data_len;
    unsigned long long int detected_flow_protocols;

    uint64_t last_idle_scan_time;
    uint64_t last_time;

    void ** ndpi_flows_active;
    unsigned long long int max_active_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int total_active_flows;

    void ** ndpi_flows_idle;
    unsigned long long int max_idle_flows;
    unsigned long long int cur_idle_flows;
    unsigned long long int total_idle_flows;

    struct ndpi_detection_module_struct *ndpi_struct;
};

struct nDPI_workflow* init_workflow(void);
char* ndpi_process_packet(struct nDPI_workflow *workflow,
                          struct pcap_pkthdr const * const header,
                          uint8_t const * const packet);
void free_workflow(struct nDPI_workflow ** const workflow);

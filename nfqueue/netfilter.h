#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

extern int GoCallbackWrapper(void *data, void *nfad);

int _process_loop(struct nfq_handle *h,
                  int fd,
                  int flags,
                  int max_count);

int c_nfq_cb(struct nfq_q_handle *qh,
             struct nfgenmsg *nfmsg,
             struct nfq_data *nfad, void *data);
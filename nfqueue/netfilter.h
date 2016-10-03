#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>

extern int GoCallbackWrapper(void *data, void *nfad);

int _process_loop(struct nfq_handle *h,
                  int fd,
                  int flags);

int c_nfq_cb(struct nfq_q_handle *qh,
             struct nfgenmsg *nfmsg,
             struct nfq_data *nfad, void *data);

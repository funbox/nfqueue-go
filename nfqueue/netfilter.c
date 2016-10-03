#include <netfilter.h>

int _process_loop(struct nfq_handle *h,
                  int fd,
                  int flags) {
        int rv;
        char buf[65535];

        while (rv = recv(fd, buf, sizeof(buf), flags)) {
                if (rv < 0) {
                  return rv;
                }

                nfq_handle_packet(h, buf, rv);
        }

        return 0;
}

int c_nfq_cb(struct nfq_q_handle *qh,
             struct nfgenmsg *nfmsg,
             struct nfq_data *nfad, void *data) {
    goCallbackWrapper(data, nfad);
  
    return 0;
}

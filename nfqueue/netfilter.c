#include <netfilter.h>

int _process_loop(struct nfq_handle *h,
                  int fd,
                  int flags,
                  int max_count) {
        int rv;
        char buf[65535];
        int count;

        count = 0;

        while ((rv = recv(fd, buf, sizeof(buf), flags)) >= 0) {
                nfq_handle_packet(h, buf, rv);
                count++;
                if (max_count > 0 && count >= max_count) {
                        break;
                }
        }
        return count;
}

int c_nfq_cb(struct nfq_q_handle *qh,
             struct nfgenmsg *nfmsg,
             struct nfq_data *nfad, void *data) {
    goCallbackWrapper(data, nfad);
    return 0;
}
/*
 * Copyright (c) 2011 Gaetano Catalli.
 * Copyright (c) 2013 YAMAMOTO Takashi.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "netdev-provider.h"
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <ifaddrs.h>
#include <pcap/pcap.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_tap.h>
#include <netinet/in.h>
#ifdef HAVE_NET_IF_MIB_H
#include <net/if_mib.h>
#endif
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>
#if defined(__NetBSD__)
#include <net/route.h>
#endif

#include "rtbsd.h"
#include "coverage.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "shash.h"
#include "svec.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_bsd);


struct netdev_rx_bsd {
    struct netdev_rx up;

    /* Packet capture descriptor for a system network device.
     * For a tap device this is NULL. */
    pcap_t *pcap_handle;

    /* Selectable file descriptor for the network device.
     * This descriptor will be used for polling operations. */
    int fd;
};

static const struct netdev_rx_class netdev_rx_bsd_class;

struct netdev_bsd {
    struct netdev up;
    unsigned int cache_valid;
    unsigned int change_seq;

    int ifindex;
    uint8_t etheraddr[ETH_ADDR_LEN];
    struct in_addr in4;
    struct in6_addr in6;
    int mtu;
    int carrier;

    int tap_fd;         /* TAP character device, if any, otherwise -1. */

    /* Used for sending packets on non-tap devices. */
    pcap_t *pcap;
    int fd;

    char *kernel_name;
};


enum {
    VALID_IFINDEX = 1 << 0,
    VALID_ETHERADDR = 1 << 1,
    VALID_IN4 = 1 << 2,
    VALID_IN6 = 1 << 3,
    VALID_MTU = 1 << 4,
    VALID_CARRIER = 1 << 5
};

/* An AF_INET socket (used for ioctl operations). */
static int af_inet_sock = -1;

#if defined(__NetBSD__)
/* AF_LINK socket used for netdev_bsd_get_stats and set_etheraddr */
static int af_link_sock = -1;
#endif /* defined(__NetBSD__) */

#define PCAP_SNAPLEN 2048


/*
 * Notifier used to invalidate device informations in case of status change.
 *
 * It will be registered with a 'rtbsd_notifier_register()' when the first
 * device will be created with the call of either 'netdev_bsd_tap_create()' or
 * 'netdev_bsd_system_create()'.
 *
 * The callback associated with this notifier ('netdev_bsd_cache_cb()') will
 * invalidate cached information about the device.
 */
static struct rtbsd_notifier netdev_bsd_cache_notifier;
static int cache_notifier_refcount;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static int netdev_bsd_do_ioctl(const char *, struct ifreq *, unsigned long cmd,
                               const char *cmd_name);
static void destroy_tap(int fd, const char *name);
static int get_flags(const struct netdev *, int *flagsp);
static int set_flags(const char *, int flags);
static int do_set_addr(struct netdev *netdev,
                       int ioctl_nr, const char *ioctl_name,
                       struct in_addr addr);
static int get_etheraddr(const char *netdev_name, uint8_t ea[ETH_ADDR_LEN]);
static int set_etheraddr(const char *netdev_name, int hwaddr_family,
                         int hwaddr_len, const uint8_t[ETH_ADDR_LEN]);
static int get_ifindex(const struct netdev *, int *ifindexp);

static int ifr_get_flags(const struct ifreq *);
static void ifr_set_flags(struct ifreq *, int flags);

static int netdev_bsd_init(void);

static bool
is_netdev_bsd_class(const struct netdev_class *netdev_class)
{
    return netdev_class->init == netdev_bsd_init;
}

static struct netdev_bsd *
netdev_bsd_cast(const struct netdev *netdev)
{
    ovs_assert(is_netdev_bsd_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_bsd, up);
}

static struct netdev_rx_bsd *
netdev_rx_bsd_cast(const struct netdev_rx *rx)
{
    netdev_rx_assert_class(rx, &netdev_rx_bsd_class);
    return CONTAINER_OF(rx, struct netdev_rx_bsd, up);
}

static const char *
netdev_get_kernel_name(const struct netdev *netdev)
{
    return netdev_bsd_cast(netdev)->kernel_name;
}

/* Initialize the AF_INET socket used for ioctl operations */
static int
netdev_bsd_init(void)
{
    static int status = -1;

    if (status >= 0) {  /* already initialized */
        return status;
    }

    af_inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
    status = af_inet_sock >= 0 ? 0 : errno;
    if (status) {
        VLOG_ERR("failed to create inet socket: %s", ovs_strerror(status));
        return status;
    }

#if defined(__NetBSD__)
    af_link_sock = socket(AF_LINK, SOCK_DGRAM, 0);
    status = af_link_sock >= 0 ? 0 : errno;
    if (status) {
        VLOG_ERR("failed to create link socket: %s", ovs_strerror(status));
        close(af_inet_sock);
        af_inet_sock = -1;
    }
#endif /* defined(__NetBSD__) */

    return status;
}

/*
 * Perform periodic work needed by netdev. In BSD netdevs it checks for any
 * interface status changes, and eventually calls all the user callbacks.
 */
static void
netdev_bsd_run(void)
{
    rtbsd_notifier_run();
}

/*
 * Arranges for poll_block() to wake up if the "run" member function needs to
 * be called.
 */
static void
netdev_bsd_wait(void)
{
    rtbsd_notifier_wait();
}

static void
netdev_bsd_changed(struct netdev_bsd *dev)
{
    dev->change_seq++;
    if (!dev->change_seq) {
        dev->change_seq++;
    }
}

/* Invalidate cache in case of interface status change. */
static void
netdev_bsd_cache_cb(const struct rtbsd_change *change,
                    void *aux OVS_UNUSED)
{
    struct netdev_bsd *dev;

    if (change) {
        struct netdev *base_dev = netdev_from_name(change->if_name);

        if (base_dev) {
            const struct netdev_class *netdev_class =
                                                netdev_get_class(base_dev);

            if (is_netdev_bsd_class(netdev_class)) {
                dev = netdev_bsd_cast(base_dev);
                dev->cache_valid = 0;
                netdev_bsd_changed(dev);
            }
        }
    } else {
        /*
         * XXX the API is lacking, we should be able to iterate on the list of
         * netdevs without having to store the info in a temp shash.
         */
        struct shash device_shash;
        struct shash_node *node;

        shash_init(&device_shash);
        netdev_get_devices(&netdev_bsd_class, &device_shash);
        SHASH_FOR_EACH (node, &device_shash) {
            dev = node->data;
            dev->cache_valid = 0;
            netdev_bsd_changed(dev);
        }
        shash_destroy(&device_shash);
    }
}

static int
cache_notifier_ref(void)
{
    int ret = 0;

    if (!cache_notifier_refcount) {
        ret = rtbsd_notifier_register(&netdev_bsd_cache_notifier,
                                                netdev_bsd_cache_cb, NULL);
        if (ret) {
            return ret;
        }
    }
    cache_notifier_refcount++;
    return 0;
}

static int
cache_notifier_unref(void)
{
    cache_notifier_refcount--;
    if (cache_notifier_refcount == 0) {
        rtbsd_notifier_unregister(&netdev_bsd_cache_notifier);
    }
    return 0;
}

/* Allocate a netdev_bsd structure */
static int
netdev_bsd_create_system(const struct netdev_class *class, const char *name,
                  struct netdev **netdevp)
{
    struct netdev_bsd *netdev;
    enum netdev_flags flags;
    int error;

    error = cache_notifier_ref();
    if (error) {
        return error;
    }

    netdev = xzalloc(sizeof *netdev);
    netdev->change_seq = 1;
    netdev_init(&netdev->up, name, class);
    netdev->tap_fd = -1;
    netdev->kernel_name = xstrdup(name);

    /* Verify that the netdev really exists by attempting to read its flags */
    error = netdev_get_flags(&netdev->up, &flags);
    if (error == ENXIO) {
        netdev_uninit(&netdev->up, false);
        free(netdev);
        cache_notifier_unref();
        return error;
    }

    *netdevp = &netdev->up;
    return 0;
}

/*
 * Allocate a netdev_bsd structure with 'tap' class.
 */
static int
netdev_bsd_create_tap(const struct netdev_class *class, const char *name,
                  struct netdev **netdevp)
{
    struct netdev_bsd *netdev = NULL;
    int error = 0;
    struct ifreq ifr;
    char *kernel_name = NULL;

    error = cache_notifier_ref();
    if (error) {
        goto error;
    }

    /* allocate the device structure and set the internal flag */
    netdev = xzalloc(sizeof *netdev);

    memset(&ifr, 0, sizeof(ifr));

    /* Create a tap device by opening /dev/tap.  The TAPGIFNAME ioctl is used
     * to retrieve the name of the tap device. */
    netdev->tap_fd = open("/dev/tap", O_RDWR);
    netdev->change_seq = 1;
    if (netdev->tap_fd < 0) {
        error = errno;
        VLOG_WARN("opening \"/dev/tap\" failed: %s", ovs_strerror(error));
        goto error_undef_notifier;
    }

    /* Retrieve tap name (e.g. tap0) */
    if (ioctl(netdev->tap_fd, TAPGIFNAME, &ifr) == -1) {
        /* XXX Need to destroy the device? */
        error = errno;
        goto error_undef_notifier;
    }

    /* Change the name of the tap device */
#if defined(SIOCSIFNAME)
    ifr.ifr_data = (void *)name;
    if (ioctl(af_inet_sock, SIOCSIFNAME, &ifr) == -1) {
        error = errno;
        destroy_tap(netdev->tap_fd, ifr.ifr_name);
        goto error_undef_notifier;
    }
    kernel_name = xstrdup(name);
#else
    /*
     * NetBSD doesn't support inteface renaming.
     */
    VLOG_INFO("tap %s is created for bridge %s", ifr.ifr_name, name);
    kernel_name = xstrdup(ifr.ifr_name);
#endif

    /* set non-blocking. */
    error = set_nonblocking(netdev->tap_fd);
    if (error) {
        destroy_tap(netdev->tap_fd, kernel_name);
        goto error_undef_notifier;
    }

    /* Turn device UP */
    ifr_set_flags(&ifr, IFF_UP);
    strncpy(ifr.ifr_name, kernel_name, sizeof ifr.ifr_name);
    if (ioctl(af_inet_sock, SIOCSIFFLAGS, &ifr) == -1) {
        error = errno;
        destroy_tap(netdev->tap_fd, kernel_name);
        goto error_undef_notifier;
    }

    /* initialize the device structure and
     * link the structure to its netdev */
    netdev_init(&netdev->up, name, class);
    netdev->kernel_name = kernel_name;
    *netdevp = &netdev->up;

    return 0;

error_undef_notifier:
    cache_notifier_unref();
error:
    free(netdev);
    free(kernel_name);
    return error;
}

static void
netdev_bsd_destroy(struct netdev *netdev_)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);

    cache_notifier_unref();

    if (netdev->tap_fd >= 0) {
        destroy_tap(netdev->tap_fd, netdev_get_kernel_name(netdev_));
    }
    if (netdev->pcap) {
        pcap_close(netdev->pcap);
    }
    free(netdev->kernel_name);
    free(netdev);
}

static int
netdev_bsd_open_pcap(const char *name, pcap_t **pcapp, int *fdp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
    int one = 1;
    int error;
    int fd;

    /* Open the pcap device.  The device is opened in non-promiscuous mode
     * because the interface flags are manually set by the caller. */
    errbuf[0] = '\0';
    pcap = pcap_open_live(name, PCAP_SNAPLEN, 0, 1000, errbuf);
    if (!pcap) {
        VLOG_ERR_RL(&rl, "%s: pcap_open_live failed: %s", name, errbuf);
        error = EIO;
        goto error;
    }
    if (errbuf[0] != '\0') {
        VLOG_WARN_RL(&rl, "%s: pcap_open_live: %s", name, errbuf);
    }

    /* Get the underlying fd. */
    fd = pcap_get_selectable_fd(pcap);
    if (fd == -1) {
        VLOG_WARN_RL(&rl, "%s: no selectable file descriptor", name);
        error = errno;
        goto error;
    }

    /* Set non-blocking mode. Also the BIOCIMMEDIATE ioctl must be called
     * on the file descriptor returned by pcap_get_selectable_fd to achieve
     * a real non-blocking behaviour.*/
    error = pcap_setnonblock(pcap, 1, errbuf);
    if (error == -1) {
        error = errno;
        goto error;
    }

    /* This call assure that reads return immediately upon packet
     * reception.  Otherwise, a read will block until either the kernel
     * buffer becomes full or a timeout occurs. */
    if (ioctl(fd, BIOCIMMEDIATE, &one) < 0 ) {
        VLOG_ERR_RL(&rl, "ioctl(BIOCIMMEDIATE) on %s device failed: %s",
                    name, ovs_strerror(errno));
        error = errno;
        goto error;
    }

    /* Capture only incoming packets. */
    error = pcap_setdirection(pcap, PCAP_D_IN);
    if (error == -1) {
        error = errno;
        goto error;
    }

    *pcapp = pcap;
    *fdp = fd;
    return 0;

error:
    if (pcap) {
        pcap_close(pcap);
    }
    *pcapp = NULL;
    *fdp = -1;
    return error;
}

static int
netdev_bsd_rx_open(struct netdev *netdev_, struct netdev_rx **rxp)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);

    struct netdev_rx_bsd *rx;
    pcap_t *pcap;
    int fd;

    if (!strcmp(netdev_get_type(netdev_), "tap")) {
        pcap = NULL;
        fd = netdev->tap_fd;
    } else {
        int error = netdev_bsd_open_pcap(netdev_get_kernel_name(netdev_),
                                         &pcap, &fd);
        if (error) {
            return error;
        }

        netdev_bsd_changed(netdev);
    }

    rx = xmalloc(sizeof *rx);
    netdev_rx_init(&rx->up, netdev_, &netdev_rx_bsd_class);
    rx->pcap_handle = pcap;
    rx->fd = fd;

    *rxp = &rx->up;
    return 0;
}

static void
netdev_rx_bsd_destroy(struct netdev_rx *rx_)
{
    struct netdev_rx_bsd *rx = netdev_rx_bsd_cast(rx_);

    if (rx->pcap_handle) {
        pcap_close(rx->pcap_handle);
    }
    free(rx);
}

/* The recv callback of the netdev class returns the number of bytes of the
 * received packet.
 *
 * This can be done by the pcap_next() function. Unfortunately pcap_next() does
 * not make difference between a missing packet on the capture interface and
 * an error during the file capture.  We can use the pcap_dispatch() function
 * instead, which is able to distinguish between errors and null packet.
 *
 * To make pcap_dispatch() returns the number of bytes read from the interface
 * we need to define the following callback and argument.
 */
struct pcap_arg {
    void *data;
    int size;
    int retval;
};

/*
 * This callback will be executed on every captured packet.
 *
 * If the packet captured by pcap_dispatch() does not fit the pcap buffer,
 * pcap returns a truncated packet and we follow this behavior.
 *
 * The argument args->retval is the packet size in bytes.
 */
static void
proc_pkt(u_char *args_, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    struct pcap_arg *args = (struct pcap_arg *)args_;

    if (args->size < hdr->len) {
        VLOG_WARN_RL(&rl, "packet truncated");
        args->retval = args->size;
    } else {
        args->retval = hdr->len;
    }

    /* copy the packet to our buffer */
    memcpy(args->data, packet, args->retval);
}

/*
 * This function attempts to receive a packet from the specified network
 * device. It is assumed that the network device is a system device or a tap
 * device opened as a system one. In this case the read operation is performed
 * from rx->pcap.
 */
static int
netdev_rx_bsd_recv_pcap(struct netdev_rx_bsd *rx, void *data, size_t size)
{
    struct pcap_arg arg;
    int ret;

    /* prepare the pcap argument to store the packet */
    arg.size = size;
    arg.data = data;

    for (;;) {
        ret = pcap_dispatch(rx->pcap_handle, 1, proc_pkt, (u_char *) &arg);

        if (ret > 0) {
            return arg.retval;	/* arg.retval < 0 is handled in the caller */
        }
        if (ret == -1) {
            if (errno == EINTR) {
                 continue;
            }
        }

        return -EAGAIN;
    }
}

/*
 * This function attempts to receive a packet from the specified network
 * device. It is assumed that the network device is a tap device and
 * 'rx->fd' is initialized with the tap file descriptor.
 */
static int
netdev_rx_bsd_recv_tap(struct netdev_rx_bsd *rx, void *data, size_t size)
{
    for (;;) {
        ssize_t retval = read(rx->fd, data, size);
        if (retval >= 0) {
            return retval;
        } else if (errno != EINTR) {
            if (errno != EAGAIN) {
                VLOG_WARN_RL(&rl, "error receiving Ethernet packet on %s: %s",
                             ovs_strerror(errno), netdev_rx_get_name(&rx->up));
            }
            return -errno;
        }
    }
}


static int
netdev_rx_bsd_recv(struct netdev_rx *rx_, void *data, size_t size)
{
    struct netdev_rx_bsd *rx = netdev_rx_bsd_cast(rx_);

    return (rx->pcap_handle
            ? netdev_rx_bsd_recv_pcap(rx, data, size)
            : netdev_rx_bsd_recv_tap(rx, data, size));
}

/*
 * Registers with the poll loop to wake up from the next call to poll_block()
 * when a packet is ready to be received with netdev_rx_recv() on 'rx'.
 */
static void
netdev_rx_bsd_wait(struct netdev_rx *rx_)
{
    struct netdev_rx_bsd *rx = netdev_rx_bsd_cast(rx_);

    poll_fd_wait(rx->fd, POLLIN);
}

/* Discards all packets waiting to be received from 'rx'. */
static int
netdev_rx_bsd_drain(struct netdev_rx *rx_)
{
    struct ifreq ifr;
    struct netdev_rx_bsd *rx = netdev_rx_bsd_cast(rx_);

    strcpy(ifr.ifr_name, netdev_get_kernel_name(netdev_rx_get_netdev(rx_)));
    if (ioctl(rx->fd, BIOCFLUSH, &ifr) == -1) {
        VLOG_DBG_RL(&rl, "%s: ioctl(BIOCFLUSH) failed: %s",
                    netdev_rx_get_name(rx_), ovs_strerror(errno));
        return errno;
    }
    return 0;
}

/*
 * Send a packet on the specified network device. The device could be either a
 * system or a tap device.
 */
static int
netdev_bsd_send(struct netdev *netdev_, const void *data, size_t size)
{
    struct netdev_bsd *dev = netdev_bsd_cast(netdev_);
    const char *name = netdev_get_name(netdev_);

    if (dev->tap_fd < 0 && !dev->pcap) {
        int error = netdev_bsd_open_pcap(name, &dev->pcap, &dev->fd);
        if (error) {
            return error;
        }
    }

    for (;;) {
        ssize_t retval;
        if (dev->tap_fd >= 0) {
            retval = write(dev->tap_fd, data, size);
        } else {
            retval = pcap_inject(dev->pcap, data, size);
        }
        if (retval < 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno != EAGAIN) {
                VLOG_WARN_RL(&rl, "error sending Ethernet packet on %s: %s",
                             name, ovs_strerror(errno));
            }
            return errno;
        } else if (retval != size) {
            VLOG_WARN_RL(&rl, "sent partial Ethernet packet (%zd bytes of "
                         "%zu) on %s", retval, size, name);
           return EMSGSIZE;
        } else {
            return 0;
        }
    }
}

/*
 * Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send().
 */
static void
netdev_bsd_send_wait(struct netdev *netdev_)
{
    struct netdev_bsd *dev = netdev_bsd_cast(netdev_);

    if (dev->tap_fd >= 0) {
        /* TAP device always accepts packets. */
        poll_immediate_wake();
    } else if (dev->pcap) {
        poll_fd_wait(dev->fd, POLLOUT);
    } else {
        /* We haven't even tried to send a packet yet. */
        poll_immediate_wake();
    }
}

/*
 * Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value.
 */
static int
netdev_bsd_set_etheraddr(struct netdev *netdev_,
                         const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);
    int error;

    if (!(netdev->cache_valid & VALID_ETHERADDR)
        || !eth_addr_equals(netdev->etheraddr, mac)) {
        error = set_etheraddr(netdev_get_kernel_name(netdev_), AF_LINK,
                              ETH_ADDR_LEN, mac);
        if (!error) {
            netdev->cache_valid |= VALID_ETHERADDR;
            memcpy(netdev->etheraddr, mac, ETH_ADDR_LEN);
            netdev_bsd_changed(netdev);
        }
    } else {
        error = 0;
    }
    return error;
}

/*
 * Returns a pointer to 'netdev''s MAC address.  The caller must not modify or
 * free the returned buffer.
 */
static int
netdev_bsd_get_etheraddr(const struct netdev *netdev_,
                         uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);

    if (!(netdev->cache_valid & VALID_ETHERADDR)) {
        int error = get_etheraddr(netdev_get_kernel_name(netdev_),
                                  netdev->etheraddr);
        if (error) {
            return error;
        }
        netdev->cache_valid |= VALID_ETHERADDR;
    }
    memcpy(mac, netdev->etheraddr, ETH_ADDR_LEN);

    return 0;
}

/*
 * Returns the maximum size of transmitted (and received) packets on 'netdev',
 * in bytes, not including the hardware header; thus, this is typically 1500
 * bytes for Ethernet devices.
 */
static int
netdev_bsd_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);

    if (!(netdev->cache_valid & VALID_MTU)) {
        struct ifreq ifr;
        int error;

        error = netdev_bsd_do_ioctl(netdev_get_kernel_name(netdev_), &ifr,
                                    SIOCGIFMTU, "SIOCGIFMTU");
        if (error) {
            return error;
        }
        netdev->mtu = ifr.ifr_mtu;
        netdev->cache_valid |= VALID_MTU;
    }

    *mtup = netdev->mtu;
    return 0;
}

static int
netdev_bsd_get_ifindex(const struct netdev *netdev)
{
    int ifindex, error;

    error = get_ifindex(netdev, &ifindex);
    return error ? -error : ifindex;
}

static int
netdev_bsd_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);

    if (!(netdev->cache_valid & VALID_CARRIER)) {
        struct ifmediareq ifmr;

        memset(&ifmr, 0, sizeof(ifmr));
        strncpy(ifmr.ifm_name, netdev_get_kernel_name(netdev_),
                sizeof ifmr.ifm_name);

        if (ioctl(af_inet_sock, SIOCGIFMEDIA, &ifmr) == -1) {
            VLOG_DBG_RL(&rl, "%s: ioctl(SIOCGIFMEDIA) failed: %s",
                        netdev_get_name(netdev_), ovs_strerror(errno));
            return errno;
        }

        netdev->carrier = (ifmr.ifm_status & IFM_ACTIVE) == IFM_ACTIVE;
        netdev->cache_valid |= VALID_CARRIER;

        /* If the interface doesn't report whether the media is active,
         * just assume it is active. */
        if ((ifmr.ifm_status & IFM_AVALID) == 0) {
            netdev->carrier = true;
        }
    }
    *carrier = netdev->carrier;

    return 0;
}

static void
convert_stats(struct netdev_stats *stats, const struct if_data *ifd)
{
    /*
     * note: UINT64_MAX means unsupported
     */
    stats->rx_packets = ifd->ifi_ipackets;
    stats->tx_packets = ifd->ifi_opackets;
    stats->rx_bytes = ifd->ifi_obytes;
    stats->tx_bytes = ifd->ifi_ibytes;
    stats->rx_errors = ifd->ifi_ierrors;
    stats->tx_errors = ifd->ifi_oerrors;
    stats->rx_dropped = ifd->ifi_iqdrops;
    stats->tx_dropped = UINT64_MAX;
    stats->multicast = ifd->ifi_imcasts;
    stats->collisions = ifd->ifi_collisions;
    stats->rx_length_errors = UINT64_MAX;
    stats->rx_over_errors = UINT64_MAX;
    stats->rx_crc_errors = UINT64_MAX;
    stats->rx_frame_errors = UINT64_MAX;
    stats->rx_fifo_errors = UINT64_MAX;
    stats->rx_missed_errors = UINT64_MAX;
    stats->tx_aborted_errors = UINT64_MAX;
    stats->tx_carrier_errors = UINT64_MAX;
    stats->tx_fifo_errors = UINT64_MAX;
    stats->tx_heartbeat_errors = UINT64_MAX;
    stats->tx_window_errors = UINT64_MAX;
}

/* Retrieves current device stats for 'netdev'. */
static int
netdev_bsd_get_stats(const struct netdev *netdev_, struct netdev_stats *stats)
{
#if defined(__FreeBSD__)
    int if_count, i;
    int mib[6];
    size_t len;
    struct ifmibdata ifmd;


    mib[0] = CTL_NET;
    mib[1] = PF_LINK;
    mib[2] = NETLINK_GENERIC;
    mib[3] = IFMIB_SYSTEM;
    mib[4] = IFMIB_IFCOUNT;

    len = sizeof(if_count);

    if (sysctl(mib, 5, &if_count, &len, (void *)0, 0) == -1) {
        VLOG_DBG_RL(&rl, "%s: sysctl failed: %s",
                    netdev_get_name(netdev_), ovs_strerror(errno));
        return errno;
    }

    mib[5] = IFDATA_GENERAL;
    mib[3] = IFMIB_IFDATA;
    len = sizeof(ifmd);
    for (i = 1; i <= if_count; i++) {
        mib[4] = i; //row
        if (sysctl(mib, 6, &ifmd, &len, (void *)0, 0) == -1) {
            VLOG_DBG_RL(&rl, "%s: sysctl failed: %s",
                        netdev_get_name(netdev_), ovs_strerror(errno));
            return errno;
        } else if (!strcmp(ifmd.ifmd_name, netdev_get_name(netdev_))) {
            convert_stats(stats, &ifmd.ifmd_data);
            break;
        }
    }

    return 0;
#elif defined(__NetBSD__)
    struct ifdatareq ifdr;
    int saved_errno;
    int ret;

    memset(&ifdr, 0, sizeof(ifdr));
    strncpy(ifdr.ifdr_name, netdev_get_kernel_name(netdev_),
            sizeof(ifdr.ifdr_name));
    ret = ioctl(af_link_sock, SIOCGIFDATA, &ifdr);
    saved_errno = errno;
    if (ret == -1) {
        return saved_errno;
    }
    convert_stats(stats, &ifdr.ifdr_data);
    return 0;
#else
#error not implemented
#endif
}

static uint32_t
netdev_bsd_parse_media(int media)
{
    uint32_t supported = 0;
    bool half_duplex = media & IFM_HDX ? true : false;

    switch (IFM_SUBTYPE(media)) {
    case IFM_10_2:
    case IFM_10_5:
    case IFM_10_STP:
    case IFM_10_T:
        supported |= half_duplex ? NETDEV_F_10MB_HD : NETDEV_F_10MB_FD;
        supported |= NETDEV_F_COPPER;
        break;

    case IFM_10_FL:
        supported |= half_duplex ? NETDEV_F_10MB_HD : NETDEV_F_10MB_FD;
        supported |= NETDEV_F_FIBER;
        break;

    case IFM_100_T2:
    case IFM_100_T4:
    case IFM_100_TX:
    case IFM_100_VG:
        supported |= half_duplex ? NETDEV_F_100MB_HD : NETDEV_F_100MB_FD;
        supported |= NETDEV_F_COPPER;
        break;

    case IFM_100_FX:
        supported |= half_duplex ? NETDEV_F_100MB_HD : NETDEV_F_100MB_FD;
        supported |= NETDEV_F_FIBER;
        break;

    case IFM_1000_CX:
    case IFM_1000_T:
        supported |= half_duplex ? NETDEV_F_1GB_HD : NETDEV_F_1GB_FD;
        supported |= NETDEV_F_COPPER;
        break;

    case IFM_1000_LX:
    case IFM_1000_SX:
        supported |= half_duplex ? NETDEV_F_1GB_HD : NETDEV_F_1GB_FD;
        supported |= NETDEV_F_FIBER;
        break;

    case IFM_10G_CX4:
        supported |= NETDEV_F_10GB_FD;
        supported |= NETDEV_F_COPPER;
        break;

    case IFM_10G_LR:
    case IFM_10G_SR:
        supported |= NETDEV_F_10GB_FD;
        supported |= NETDEV_F_FIBER;
        break;

    default:
        return 0;
    }

    if (IFM_SUBTYPE(media) == IFM_AUTO) {
        supported |= NETDEV_F_AUTONEG;
    }
    /*
    if (media & IFM_ETH_FMASK) {
        supported |= NETDEV_F_PAUSE;
    }
    */

    return supported;
}

/*
 * Stores the features supported by 'netdev' into each of '*current',
 * '*advertised', '*supported', and '*peer' that are non-null.  Each value is a
 * bitmap of "enum ofp_port_features" bits, in host byte order.  Returns 0 if
 * successful, otherwise a positive errno value.  On failure, all of the
 * passed-in values are set to 0.
 */
static int
netdev_bsd_get_features(const struct netdev *netdev,
                        enum netdev_features *current, uint32_t *advertised,
                        enum netdev_features *supported, uint32_t *peer)
{
    struct ifmediareq ifmr;
    int *media_list;
    int i;
    int error;


    /* XXX Look into SIOCGIFCAP instead of SIOCGIFMEDIA */

    memset(&ifmr, 0, sizeof(ifmr));
    strncpy(ifmr.ifm_name, netdev_get_name(netdev), sizeof ifmr.ifm_name);

    /* We make two SIOCGIFMEDIA ioctl calls.  The first to determine the
     * number of supported modes, and a second with a buffer to retrieve
     * them. */
    if (ioctl(af_inet_sock, SIOCGIFMEDIA, &ifmr) == -1) {
        VLOG_DBG_RL(&rl, "%s: ioctl(SIOCGIFMEDIA) failed: %s",
                    netdev_get_name(netdev), ovs_strerror(errno));
        return errno;
    }

    media_list = xcalloc(ifmr.ifm_count, sizeof(int));
    ifmr.ifm_ulist = media_list;

    if (IFM_TYPE(ifmr.ifm_current) != IFM_ETHER) {
        VLOG_DBG_RL(&rl, "%s: doesn't appear to be ethernet",
                    netdev_get_name(netdev));
        error = EINVAL;
        goto cleanup;
    }

    if (ioctl(af_inet_sock, SIOCGIFMEDIA, &ifmr) == -1) {
        VLOG_DBG_RL(&rl, "%s: ioctl(SIOCGIFMEDIA) failed: %s",
                    netdev_get_name(netdev), ovs_strerror(errno));
        error = errno;
        goto cleanup;
    }

    /* Current settings. */
    *current = netdev_bsd_parse_media(ifmr.ifm_active);

    /* Advertised features. */
    *advertised = netdev_bsd_parse_media(ifmr.ifm_current);

    /* Supported features. */
    *supported = 0;
    for (i = 0; i < ifmr.ifm_count; i++) {
        *supported |= netdev_bsd_parse_media(ifmr.ifm_ulist[i]);
    }

    /* Peer advertisements. */
    *peer = 0;                  /* XXX */

    error = 0;
cleanup:
    free(media_list);
    return error;
}

/*
 * If 'netdev' has an assigned IPv4 address, sets '*in4' to that address (if
 * 'in4' is non-null) and returns true.  Otherwise, returns false.
 */
static int
netdev_bsd_get_in4(const struct netdev *netdev_, struct in_addr *in4,
                   struct in_addr *netmask)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);

    if (!(netdev->cache_valid & VALID_IN4)) {
        const struct sockaddr_in *sin;
        struct ifreq ifr;
        int error;

        ifr.ifr_addr.sa_family = AF_INET;
        error = netdev_bsd_do_ioctl(netdev_get_kernel_name(netdev_), &ifr,
                                    SIOCGIFADDR, "SIOCGIFADDR");
        if (error) {
            return error;
        }

        sin = (struct sockaddr_in *) &ifr.ifr_addr;
        netdev->in4 = sin->sin_addr;
        netdev->cache_valid |= VALID_IN4;
        error = netdev_bsd_do_ioctl(netdev_get_kernel_name(netdev_), &ifr,
                                    SIOCGIFNETMASK, "SIOCGIFNETMASK");
        if (error) {
            return error;
        }
        *netmask = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
    }
    *in4 = netdev->in4;

    return in4->s_addr == INADDR_ANY ? EADDRNOTAVAIL : 0;
}

/*
 * Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
 * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.  Returns a
 * positive errno value.
 */
static int
netdev_bsd_set_in4(struct netdev *netdev_, struct in_addr addr,
                   struct in_addr mask)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);
    int error;

    error = do_set_addr(netdev_, SIOCSIFADDR, "SIOCSIFADDR", addr);
    if (!error) {
        netdev->cache_valid |= VALID_IN4;
        netdev->in4 = addr;
        if (addr.s_addr != INADDR_ANY) {
            error = do_set_addr(netdev_, SIOCSIFNETMASK,
                                "SIOCSIFNETMASK", mask);
        }
        netdev_bsd_changed(netdev);
    }
    return error;
}

static int
netdev_bsd_get_in6(const struct netdev *netdev_, struct in6_addr *in6)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);
    if (!(netdev->cache_valid & VALID_IN6)) {
        struct ifaddrs *ifa, *head;
        struct sockaddr_in6 *sin6;
        const char *netdev_name = netdev_get_name(netdev_);

        if (getifaddrs(&head) != 0) {
            VLOG_ERR("getifaddrs on %s device failed: %s", netdev_name,
                    ovs_strerror(errno));
            return errno;
        }

        for (ifa = head; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr->sa_family == AF_INET6 &&
                    !strcmp(ifa->ifa_name, netdev_name)) {
                sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                if (sin6) {
                    memcpy(&netdev->in6, &sin6->sin6_addr, sin6->sin6_len);
                    netdev->cache_valid |= VALID_IN6;
                    *in6 = netdev->in6;
                    freeifaddrs(head);
                    return 0;
                }
            }
        }
        return EADDRNOTAVAIL;
    }
    *in6 = netdev->in6;
    return 0;
}

#if defined(__NetBSD__)
static struct netdev *
find_netdev_by_kernel_name(const char *kernel_name)
{
    struct shash device_shash;
    struct shash_node *node;

    shash_init(&device_shash);
    netdev_get_devices(&netdev_tap_class, &device_shash);
    SHASH_FOR_EACH(node, &device_shash) {
        struct netdev_bsd * const dev = node->data;

        if (!strcmp(dev->kernel_name, kernel_name)) {
            shash_destroy(&device_shash);
            return &dev->up;
        }
    }
    shash_destroy(&device_shash);
    return NULL;
}

static const char *
netdev_bsd_convert_kernel_name_to_ovs_name(const char *kernel_name)
{
    const struct netdev * const netdev =
      find_netdev_by_kernel_name(kernel_name);

    if (netdev == NULL) {
        return NULL;
    }
    return netdev_get_name(netdev);
}
#endif

static int
netdev_bsd_get_next_hop(const struct in_addr *host OVS_UNUSED,
                        struct in_addr *next_hop OVS_UNUSED,
                        char **netdev_name OVS_UNUSED)
{
#if defined(__NetBSD__)
    static int seq = 0;
    struct sockaddr_in sin;
    struct sockaddr_dl sdl;
    int s;
    int i;
    struct {
        struct rt_msghdr h;
        char space[512];
    } buf;
    struct rt_msghdr *rtm = &buf.h;
    const pid_t pid = getpid();
    char *cp;
    ssize_t ssz;
    bool gateway = false;
    char *ifname = NULL;
    int saved_errno;

    memset(next_hop, 0, sizeof(*next_hop));
    *netdev_name = NULL;

    memset(&sin, 0, sizeof(sin));
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    sin.sin_addr = *host;

    memset(&sdl, 0, sizeof(sdl));
    sdl.sdl_len = sizeof(sdl);
    sdl.sdl_family = AF_LINK;

    s = socket(PF_ROUTE, SOCK_RAW, 0);
    memset(&buf, 0, sizeof(buf));
    rtm->rtm_flags = RTF_HOST|RTF_UP;
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_addrs = RTA_DST|RTA_IFP;
    cp = (void *)&buf.space;
    memcpy(cp, &sin, sizeof(sin));
    RT_ADVANCE(cp, (struct sockaddr *)(void *)&sin);
    memcpy(cp, &sdl, sizeof(sdl));
    RT_ADVANCE(cp, (struct sockaddr *)(void *)&sdl);
    rtm->rtm_msglen = cp - (char *)(void *)rtm;
    rtm->rtm_seq = ++seq;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_pid = pid;
    write(s, rtm, rtm->rtm_msglen);
    memset(&buf, 0, sizeof(buf));
    do {
        ssz = read(s, &buf, sizeof(buf));
    } while (ssz > 0 && (rtm->rtm_seq != seq || rtm->rtm_pid != pid));
    saved_errno = errno;
    close(s);
    if (ssz <= 0) {
        if (ssz < 0) {
            return saved_errno;
        }
        return EPIPE; /* XXX */
    }
    cp = (void *)&buf.space;
    for (i = 1; i; i <<= 1) {
        if ((rtm->rtm_addrs & i) != 0) {
            const struct sockaddr *sa = (const void *)cp;

            if ((i == RTA_GATEWAY) && sa->sa_family == AF_INET) {
                const struct sockaddr_in * const sin =
                  (const struct sockaddr_in *)sa;

                *next_hop = sin->sin_addr;
                gateway = true;
            }
            if ((i == RTA_IFP) && sa->sa_family == AF_LINK) {
                const struct sockaddr_dl * const sdl =
                  (const struct sockaddr_dl *)sa;
                const size_t nlen = sdl->sdl_nlen;
                char * const kernel_name = xmalloc(nlen + 1);
                const char *name;

                memcpy(kernel_name, sdl->sdl_data, nlen);
                kernel_name[nlen] = 0;
                name = netdev_bsd_convert_kernel_name_to_ovs_name(kernel_name);
                if (name == NULL) {
                    ifname = xstrdup(kernel_name);
                } else {
                    ifname = xstrdup(name);
                }
                free(kernel_name);
            }
            RT_ADVANCE(cp, sa);
        }
    }
    if (ifname == NULL) {
        return ENXIO;
    }
    if (!gateway) {
        *next_hop = *host;
    }
    *netdev_name = ifname;
    VLOG_DBG("host " IP_FMT " next-hop " IP_FMT " if %s",
      IP_ARGS(host->s_addr), IP_ARGS(next_hop->s_addr), *netdev_name);
    return 0;
#else
    return EOPNOTSUPP;
#endif
}

static void
make_in4_sockaddr(struct sockaddr *sa, struct in_addr addr)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr = addr;
    sin.sin_port = 0;

    memset(sa, 0, sizeof *sa);
    memcpy(sa, &sin, sizeof sin);
}

static int
do_set_addr(struct netdev *netdev,
            int ioctl_nr, const char *ioctl_name, struct in_addr addr)
{
    struct ifreq ifr;
    make_in4_sockaddr(&ifr.ifr_addr, addr);
    return netdev_bsd_do_ioctl(netdev_get_kernel_name(netdev), &ifr, ioctl_nr,
                               ioctl_name);
}

static int
nd_to_iff_flags(enum netdev_flags nd)
{
    int iff = 0;
    if (nd & NETDEV_UP) {
        iff |= IFF_UP;
    }
    if (nd & NETDEV_PROMISC) {
        iff |= IFF_PROMISC;
#if defined(IFF_PPROMISC)
        iff |= IFF_PPROMISC;
#endif
    }
    return iff;
}

static int
iff_to_nd_flags(int iff)
{
    enum netdev_flags nd = 0;
    if (iff & IFF_UP) {
        nd |= NETDEV_UP;
    }
    if (iff & IFF_PROMISC) {
        nd |= NETDEV_PROMISC;
    }
    return nd;
}

static int
netdev_bsd_update_flags(struct netdev *netdev_, enum netdev_flags off,
                        enum netdev_flags on, enum netdev_flags *old_flagsp)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);
    int old_flags, new_flags;
    int error;

    error = get_flags(netdev_, &old_flags);
    if (!error) {
        *old_flagsp = iff_to_nd_flags(old_flags);
        new_flags = (old_flags & ~nd_to_iff_flags(off)) | nd_to_iff_flags(on);
        if (new_flags != old_flags) {
            error = set_flags(netdev_get_kernel_name(netdev_), new_flags);
            netdev_bsd_changed(netdev);
        }
    }
    return error;
}

static unsigned int
netdev_bsd_change_seq(const struct netdev *netdev)
{
    return netdev_bsd_cast(netdev)->change_seq;
}


const struct netdev_class netdev_bsd_class = {
    "system",

    netdev_bsd_init,
    netdev_bsd_run,
    netdev_bsd_wait,
    netdev_bsd_create_system,
    netdev_bsd_destroy,
    NULL, /* get_config */
    NULL, /* set_config */
    NULL, /* get_tunnel_config */

    netdev_bsd_rx_open,

    netdev_bsd_send,
    netdev_bsd_send_wait,

    netdev_bsd_set_etheraddr,
    netdev_bsd_get_etheraddr,
    netdev_bsd_get_mtu,
    NULL, /* set_mtu */
    netdev_bsd_get_ifindex,
    netdev_bsd_get_carrier,
    NULL, /* get_carrier_resets */
    NULL, /* set_miimon_interval */
    netdev_bsd_get_stats,
    NULL, /* set_stats */

    netdev_bsd_get_features,
    NULL, /* set_advertisement */
    NULL, /* set_policing */
    NULL, /* get_qos_type */
    NULL, /* get_qos_capabilities */
    NULL, /* get_qos */
    NULL, /* set_qos */
    NULL, /* get_queue */
    NULL, /* set_queue */
    NULL, /* delete_queue */
    NULL, /* get_queue_stats */
    NULL, /* dump_queue */
    NULL, /* dump_queue_stats */

    netdev_bsd_get_in4,
    netdev_bsd_set_in4,
    netdev_bsd_get_in6,
    NULL, /* add_router */
    netdev_bsd_get_next_hop,
    NULL, /* get_status */
    NULL, /* arp_lookup */

    netdev_bsd_update_flags,

    netdev_bsd_change_seq
};

const struct netdev_class netdev_tap_class = {
    "tap",

    netdev_bsd_init,
    netdev_bsd_run,
    netdev_bsd_wait,
    netdev_bsd_create_tap,
    netdev_bsd_destroy,
    NULL, /* get_config */
    NULL, /* set_config */
    NULL, /* get_tunnel_config */

    netdev_bsd_rx_open,

    netdev_bsd_send,
    netdev_bsd_send_wait,

    netdev_bsd_set_etheraddr,
    netdev_bsd_get_etheraddr,
    netdev_bsd_get_mtu,
    NULL, /* set_mtu */
    netdev_bsd_get_ifindex,
    netdev_bsd_get_carrier,
    NULL, /* get_carrier_resets */
    NULL, /* set_miimon_interval */
    netdev_bsd_get_stats,
    NULL, /* set_stats */

    netdev_bsd_get_features,
    NULL, /* set_advertisement */
    NULL, /* set_policing */
    NULL, /* get_qos_type */
    NULL, /* get_qos_capabilities */
    NULL, /* get_qos */
    NULL, /* set_qos */
    NULL, /* get_queue */
    NULL, /* set_queue */
    NULL, /* delete_queue */
    NULL, /* get_queue_stats */
    NULL, /* dump_queue */
    NULL, /* dump_queue_stats */

    netdev_bsd_get_in4,
    netdev_bsd_set_in4,
    netdev_bsd_get_in6,
    NULL, /* add_router */
    netdev_bsd_get_next_hop,
    NULL, /* get_status */
    NULL, /* arp_lookup */

    netdev_bsd_update_flags,

    netdev_bsd_change_seq
};

static const struct netdev_rx_class netdev_rx_bsd_class = {
    netdev_rx_bsd_destroy,
    netdev_rx_bsd_recv,
    netdev_rx_bsd_wait,
    netdev_rx_bsd_drain,
};


static void
destroy_tap(int fd, const char *name)
{
    struct ifreq ifr;

    close(fd);
    strcpy(ifr.ifr_name, name);
    /* XXX What to do if this call fails? */
    ioctl(af_inet_sock, SIOCIFDESTROY, &ifr);
}

static int
get_flags(const struct netdev *netdev, int *flags)
{
    struct ifreq ifr;
    int error;

    error = netdev_bsd_do_ioctl(netdev_get_kernel_name(netdev), &ifr,
                                SIOCGIFFLAGS, "SIOCGIFFLAGS");

    *flags = ifr_get_flags(&ifr);

    return error;
}

static int
set_flags(const char *name, int flags)
{
    struct ifreq ifr;

    ifr_set_flags(&ifr, flags);

    return netdev_bsd_do_ioctl(name, &ifr, SIOCSIFFLAGS, "SIOCSIFFLAGS");
}

static int
get_ifindex(const struct netdev *netdev_, int *ifindexp)
{
    struct netdev_bsd *netdev = netdev_bsd_cast(netdev_);
    *ifindexp = 0;
    if (!(netdev->cache_valid & VALID_IFINDEX)) {
        int ifindex = if_nametoindex(netdev_get_name(netdev_));
        if (ifindex <= 0) {
            return errno;
        }
        netdev->cache_valid |= VALID_IFINDEX;
        netdev->ifindex = ifindex;
    }
    *ifindexp = netdev->ifindex;
    return 0;
}

static int
get_etheraddr(const char *netdev_name, uint8_t ea[ETH_ADDR_LEN])
{
    struct ifaddrs *head;
    struct ifaddrs *ifa;
    struct sockaddr_dl *sdl;

    if (getifaddrs(&head) != 0) {
        VLOG_ERR("getifaddrs on %s device failed: %s", netdev_name,
                ovs_strerror(errno));
        return errno;
    }

    for (ifa = head; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            if (!strcmp(ifa->ifa_name, netdev_name)) {
                sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                if (sdl) {
                    memcpy(ea, LLADDR(sdl), sdl->sdl_alen);
                    freeifaddrs(head);
                    return 0;
                }
            }
        }
    }

    VLOG_ERR("could not find ethernet address for %s device", netdev_name);
    freeifaddrs(head);
    return ENODEV;
}

static int
set_etheraddr(const char *netdev_name OVS_UNUSED, int hwaddr_family OVS_UNUSED,
              int hwaddr_len OVS_UNUSED,
              const uint8_t mac[ETH_ADDR_LEN] OVS_UNUSED)
{
#if defined(__FreeBSD__)
    struct ifreq ifr;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    ifr.ifr_addr.sa_family = hwaddr_family;
    ifr.ifr_addr.sa_len = hwaddr_len;
    memcpy(ifr.ifr_addr.sa_data, mac, hwaddr_len);
    if (ioctl(af_inet_sock, SIOCSIFLLADDR, &ifr) < 0) {
        VLOG_ERR("ioctl(SIOCSIFLLADDR) on %s device failed: %s",
                 netdev_name, ovs_strerror(errno));
        return errno;
    }
    return 0;
#elif defined(__NetBSD__)
    struct if_laddrreq req;
    struct sockaddr_dl *sdl;
    struct sockaddr_storage oldaddr;
    int ret;

    /*
     * get the old address, add new one, and then remove old one.
     */

    if (hwaddr_len != ETH_ADDR_LEN) {
        /* just to be safe about sockaddr storage size */
        return EOPNOTSUPP;
    }
    memset(&req, 0, sizeof(req));
    strncpy(req.iflr_name, netdev_name, sizeof(req.iflr_name));
    req.addr.ss_len = sizeof(req.addr);
    req.addr.ss_family = hwaddr_family;
    sdl = (struct sockaddr_dl *)&req.addr;
    sdl->sdl_alen = hwaddr_len;
    ret = ioctl(af_link_sock, SIOCGLIFADDR, &req);
    if (ret == -1) {
        return errno;
    }
    if (!memcmp(&sdl->sdl_data[sdl->sdl_nlen], mac, hwaddr_len)) {
        return 0;
    }
    oldaddr = req.addr;

    memset(&req, 0, sizeof(req));
    strncpy(req.iflr_name, netdev_name, sizeof(req.iflr_name));
    req.flags = IFLR_ACTIVE;
    sdl = (struct sockaddr_dl *)&req.addr;
    sdl->sdl_len = offsetof(struct sockaddr_dl, sdl_data) + hwaddr_len;
    sdl->sdl_alen = hwaddr_len;
    sdl->sdl_family = hwaddr_family;
    memcpy(sdl->sdl_data, mac, hwaddr_len);
    ret = ioctl(af_link_sock, SIOCALIFADDR, &req);
    if (ret == -1) {
        return errno;
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.iflr_name, netdev_name, sizeof(req.iflr_name));
    req.addr = oldaddr;
    ret = ioctl(af_link_sock, SIOCDLIFADDR, &req);
    if (ret == -1) {
        return errno;
    }
    return 0;
#else
#error not implemented
#endif
}

static int
netdev_bsd_do_ioctl(const char *name, struct ifreq *ifr, unsigned long cmd,
                    const char *cmd_name)
{
    strncpy(ifr->ifr_name, name, sizeof ifr->ifr_name);
    if (ioctl(af_inet_sock, cmd, ifr) == -1) {
        VLOG_DBG_RL(&rl, "%s: ioctl(%s) failed: %s", name, cmd_name,
                    ovs_strerror(errno));
        return errno;
    }
    return 0;
}

static int
ifr_get_flags(const struct ifreq *ifr)
{
#ifdef HAVE_STRUCT_IFREQ_IFR_FLAGSHIGH
    return (ifr->ifr_flagshigh << 16) | ifr->ifr_flags;
#else
    return ifr->ifr_flags;
#endif
}

static void
ifr_set_flags(struct ifreq *ifr, int flags)
{
    ifr->ifr_flags = flags;
#ifdef HAVE_STRUCT_IFREQ_IFR_FLAGSHIGH
    ifr->ifr_flagshigh = flags >> 16;
#endif
}

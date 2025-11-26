#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/tcp.h>
#include <math.h>
#include <poll.h>
#include <unistd.h>

//抓包基于AF_PACKET+MMAP，使用TPACKET_V3，帧在块中紧凑存放，内存利用率高
#define BLOCK_SIZE        (1 << 17)  //每个块128KB空间
#define BLOCK_NR          8          //分配8个块
#define FRAME_SIZE        1024       //每个帧2KB长度存储
#define POLL_TIMEOUT_MS   100        //poll超时时间

#define MASK_24 0xFFFFFF00U          //255.255.255.0
#define WIN_LEN 1                  //时间窗口长度1秒
#define INITIAL_SIZE 512             //数组初始大小，后续可动态扩容
#define MAX_PACKETS 5000             //时间窗口只记录和分析最多5000个包
#define FEATURES_NUM 14              //特征维度
#define LABELS_NUM 8                 //8种流量标签
#define LABELS {"BENIGN", "SYN_FLOOD", "ACK_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "IGMP_FLOOD", "PORTSCAN", "IP_FLOOD"}

typedef struct {
    //数组类别
    uint32_t *src_ips;
    size_t ips_count;
    size_t ips_capacity;

    uint16_t *dst_ports;
    size_t ports_count;
    size_t ports_capacity;

    uint16_t *packet_sizes;
    size_t sizes_count;
    size_t sizes_capacity;

    //计数器类别
    uint64_t p_count;
    uint64_t syn_count;
    uint64_t ack_count;
    uint64_t tcp_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t igmp_count;
    uint64_t fragment_count;
    uint64_t broadcast_count;
    uint64_t multicast_count;
    uint64_t tcp_flag_anomaly;

    uint64_t uplink_packet_count;
    uint64_t downlink_packet_count;
    uint64_t upload_payload_len;
    uint64_t download_payload_len;

} Packet_Window;

void add_vectors(double *v1, double *v2, int size, double *result);
void mul_vector_number(double *v1, double num, int size, double *result);
void score(double * input, double * output);

static int ensure_capacity(void **array_ptr, size_t *count, size_t *capacity, size_t elem_size);//数组动态扩容

void init_window_stat(Packet_Window *window);//初始化包时间窗口

int is_private_ip(uint32_t ip, uint32_t local_ip, uint32_t mask); //判断ip是否是子网IP

int get_interface_ip(const char *iface, uint32_t *ip_out); //从网口名获取local_ip

int is_multicast(uint32_t ip);//判断ip是否是组播地址

int add_src_ip(Packet_Window *win, uint32_t ip);//为window->src_ips添加一个源IP地址

int add_dst_port(Packet_Window *win, uint16_t port);//为window->dst_ports添加一个目标端口

int add_packet_size(Packet_Window *win, uint16_t size);//为window->packet_sizes添加一个包大小

int compare_uint32(const void *a, const void *b);//比较函数，用于uint32的qsort

int compare_uint16(const void *a, const void *b);//比较函数，用于uint16的qsort

int count_unique_ips(uint32_t *src_ips, size_t ips_count);//计算src_ips数组中不同元素的个数

int count_unique_ports(uint16_t *dst_ports, size_t ports_count);//计算dst_ports数组中不同元素的个数

int analyze_and_update_win(Packet_Window *win, char* buffer, uint32_t *local_ip, int max_packets);//解析数据包头部，并更新window

int compute_feature(Packet_Window *win, double* features, uint8_t timeval);//计算窗口特征

int argmax(double *arr, int size);//从概率分布中获取MAX标签

int predict(double* features);//模型推理

void add_vectors(double *v1, double *v2, int size, double *result) {
    for(int i = 0; i < size; ++i)
        result[i] = v1[i] + v2[i];
}

void mul_vector_number(double *v1, double num, int size, double *result) {
    for(int i = 0; i < size; ++i)
        result[i] = v1[i] * num;
}

void score(double * input, double * output) {
    double var0[8];
    double var1[8];
    double var2[8];
    double var3[8];
    double var4[8];
    double var5[8];
    double var6[8];
    double var7[8];
    double var8[8];
    double var9[8];
    double var10[8];
    double var11[8];
    double var12[8];
    double var13[8];
    double var14[8];
    double var15[8];
    double var16[8];
    double var17[8];
    double var18[8];
    double var19[8];
    double var20[8];
    double var21[8];
    double var22[8];
    double var23[8];
    double var24[8];
    double var25[8];
    double var26[8];
    double var27[8];
    double var28[8];
    double var29[8];
    double var30[8];
    double var31[8];
    double var32[8];
    double var33[8];
    double var34[8];
    double var35[8];
    double var36[8];
    double var37[8];
    double var38[8];
    double var39[8];
    double var40[8];
    double var41[8];
    double var42[8];
    double var43[8];
    double var44[8];
    double var45[8];
    double var46[8];
    double var47[8];
    double var48[8];
    double var49[8];
    double var50[8];
    if ((input[0]) <= (129.0)) {
        if ((input[0]) <= (104.5)) {
            memcpy(var50, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
        } else {
            if ((input[1]) <= (72762.0)) {
                if ((input[10]) <= (0.43809524178504944)) {
                    if ((input[4]) <= (26.0)) {
                        if ((input[9]) <= (0.02311266027390957)) {
                            memcpy(var50, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var50, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var50, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var50, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var50, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[2]) <= (119.5469856262207)) {
                if ((input[12]) <= (0.37420592457056046)) {
                    if ((input[7]) <= (0.3343241736292839)) {
                        if ((input[8]) <= (0.36459649878088385)) {
                            memcpy(var50, (double[]){0.024639878695981804, 0.34874905231235787, 0.3502653525398029, 0.0, 0.0, 0.0, 0.27634571645185746, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var50, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var50, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var50, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[0]) <= (3126.0)) {
                    if ((input[1]) <= (613964.5)) {
                        if ((input[7]) <= (0.7156559228897095)) {
                            memcpy(var50, (double[]){0.3717948717948718, 0.017094017094017096, 0.004273504273504274, 0.0, 0.4829059829059829, 0.02564102564102564, 0.09829059829059829, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var50, (double[]){0.8301282051282052, 0.0, 0.0, 0.16025641025641027, 0.009615384615384616, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (611.517822265625)) {
                            memcpy(var50, (double[]){0.97, 0.0, 0.0, 0.0, 0.03, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var50, (double[]){0.8854166666666666, 0.0, 0.0, 0.0, 0.0, 0.0, 0.11458333333333333, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[1]) <= (577189.5)) {
                        if ((input[5]) <= (38.0)) {
                            memcpy(var50, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var50, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (665.9503173828125)) {
                            memcpy(var50, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var50, (double[]){0.978448275862069, 0.017241379310344827, 0.0, 0.0, 0.0, 0.0, 0.004310344827586207, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var50, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    }
    double var51[8];
    if ((input[10]) <= (0.04062318056821823)) {
        if ((input[0]) <= (152.5)) {
            if ((input[9]) <= (0.6465035080909729)) {
                if ((input[6]) <= (0.9926470518112183)) {
                    if ((input[4]) <= (28.0)) {
                        if ((input[13]) <= (0.3004273623228073)) {
                            memcpy(var51, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){0.9411764705882353, 0.0, 0.058823529411764705, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var51, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[4]) <= (8.0)) {
                        if ((input[2]) <= (498.82672119140625)) {
                            memcpy(var51, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (134.0)) {
                            memcpy(var51, (double[]){0.6666666666666666, 0.0, 0.3333333333333333, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var51, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[7]) <= (0.6943496465682983)) {
                if ((input[3]) <= (427.5490417480469)) {
                    if ((input[13]) <= (0.793789803981781)) {
                        if ((input[12]) <= (0.37220626324415207)) {
                            memcpy(var51, (double[]){0.0429726996966633, 0.019716885743174924, 0.4277047522750253, 0.0, 0.38473205257836196, 0.0, 0.12487360970677452, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (41.800851821899414)) {
                            memcpy(var51, (double[]){0.0, 0.36281179138321995, 0.0, 0.0, 0.08616780045351474, 0.02040816326530612, 0.5306122448979592, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){0.0, 0.7537840565085772, 0.0, 0.0, 0.005045408678102927, 0.0010090817356205853, 0.2401614530776993, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (15.5)) {
                        if ((input[6]) <= (0.7948306202888489)) {
                            memcpy(var51, (double[]){0.0, 0.0, 0.0, 0.0, 0.9743589743589743, 0.02564102564102564, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){0.9393939393939394, 0.06060606060606061, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.29987630248069763)) {
                            memcpy(var51, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){0.9790382244143033, 0.0, 0.0, 0.0, 0.0, 0.0, 0.02096177558569667, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[3]) <= (110.40787124633789)) {
                    if ((input[0]) <= (399.5)) {
                        if ((input[5]) <= (12.5)) {
                            memcpy(var51, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var51, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[5]) <= (13.5)) {
                        if ((input[3]) <= (419.21913146972656)) {
                            memcpy(var51, (double[]){0.02857142857142857, 0.0, 0.0, 0.9714285714285714, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var51, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var51, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    } else {
        memcpy(var51, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var50, var51, 8, var49);
    double var52[8];
    if ((input[5]) <= (15.5)) {
        if ((input[1]) <= (4886.5)) {
            if ((input[12]) <= (0.8557692170143127)) {
                if ((input[2]) <= (14.110429763793945)) {
                    memcpy(var52, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[4]) <= (44.5)) {
                        memcpy(var52, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var52, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[10]) <= (0.16251353919506073)) {
                if ((input[9]) <= (0.3563771191984415)) {
                    if ((input[7]) <= (0.7269444465637207)) {
                        if ((input[13]) <= (0.8275773227214813)) {
                            memcpy(var52, (double[]){0.027085590465872156, 0.017876489707475622, 0.48212351029252437, 0.0027085590465872156, 0.47020585048754066, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var52, (double[]){0.0, 0.9585106382978723, 0.0, 0.0, 0.04148936170212766, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (3.5)) {
                            memcpy(var52, (double[]){0.45384615384615384, 0.0, 0.0, 0.5461538461538461, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var52, (double[]){0.001358695652173913, 0.0, 0.0, 0.9972826086956522, 0.001358695652173913, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[3]) <= (70.85153198242188)) {
            if ((input[6]) <= (0.9782557785511017)) {
                if ((input[1]) <= (6896.0)) {
                    memcpy(var52, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[10]) <= (0.41404011845588684)) {
                        if ((input[0]) <= (247.5)) {
                            memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var52, (double[]){0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[7]) <= (0.006170660024508834)) {
                    if ((input[0]) <= (8873.5)) {
                        memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var52, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[1]) <= (15341.0)) {
                        memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[0]) <= (1264.0)) {
                            memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var52, (double[]){0.0, 0.0, 0.125, 0.0, 0.0, 0.0, 0.875, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[10]) <= (0.04062318056821823)) {
                if ((input[2]) <= (101.5223388671875)) {
                    if ((input[1]) <= (121170.0)) {
                        if ((input[7]) <= (0.10027418658137321)) {
                            memcpy(var52, (double[]){0.039603960396039604, 0.0, 0.0, 0.0, 0.0, 0.009900990099009901, 0.9504950495049505, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var52, (double[]){0.6, 0.0, 0.0, 0.0, 0.2, 0.0, 0.2, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (19697.5)) {
                            memcpy(var52, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var52, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[7]) <= (0.000027694693926605396)) {
                        if ((input[13]) <= (0.021164086647331715)) {
                            memcpy(var52, (double[]){0.9966442953020134, 0.0, 0.0, 0.0, 0.0, 0.0, 0.003355704697986577, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var52, (double[]){0.12, 0.0, 0.0, 0.0, 0.0, 0.0, 0.88, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (7.5)) {
                            memcpy(var52, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var52, (double[]){0.9908015768725361, 0.0, 0.0, 0.0, 0.0, 0.0, 0.009198423127463863, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var52, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var49, var52, 8, var48);
    double var53[8];
    if ((input[2]) <= (85.24874496459961)) {
        if ((input[5]) <= (1430.5)) {
            if ((input[1]) <= (3799.0)) {
                memcpy(var53, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[0]) <= (759.5)) {
                    if ((input[10]) <= (0.37704917788505554)) {
                        if ((input[4]) <= (40.5)) {
                            memcpy(var53, (double[]){0.00437636761487965, 0.010940919037199124, 0.3479212253829322, 0.024070021881838075, 0.08315098468271334, 0.5295404814004376, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var53, (double[]){0.0, 0.024390243902439025, 0.49477351916376305, 0.3240418118466899, 0.156794425087108, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var53, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[8]) <= (0.43371736188419163)) {
                        if ((input[13]) <= (0.8692439794540405)) {
                            memcpy(var53, (double[]){0.01856763925729443, 0.02586206896551724, 0.3421750663129973, 0.4542440318302387, 0.0, 0.08885941644562334, 0.0, 0.07029177718832891}, 8 * sizeof(double));
                        } else {
                            memcpy(var53, (double[]){0.0, 0.9320276497695853, 0.0, 0.06336405529953917, 0.0, 0.004608294930875576, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var53, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            memcpy(var53, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[9]) <= (0.032771761529147625)) {
                if ((input[3]) <= (21.888046264648438)) {
                    memcpy(var53, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[0]) <= (3285.0)) {
                        if ((input[5]) <= (3026.0)) {
                            memcpy(var53, (double[]){0.8880918220946915, 0.0028694404591104736, 0.005738880918220947, 0.017934002869440458, 0.08536585365853659, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var53, (double[]){0.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (1304.0)) {
                            memcpy(var53, (double[]){0.9876265466816648, 0.0044994375703037125, 0.0, 0.0, 0.003374578177727784, 0.0, 0.0044994375703037125, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var53, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[0]) <= (481.0)) {
                    memcpy(var53, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var53, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            memcpy(var53, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    }
    add_vectors(var48, var53, 8, var47);
    double var54[8];
    if ((input[10]) <= (0.0609900988638401)) {
        if ((input[9]) <= (0.47132131457328796)) {
            if ((input[8]) <= (0.43390804529190063)) {
                if ((input[3]) <= (115.33787155151367)) {
                    if ((input[0]) <= (154.5)) {
                        memcpy(var54, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[6]) <= (0.5743546113371849)) {
                            memcpy(var54, (double[]){0.034292035398230086, 0.0, 0.0, 0.9657079646017699, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var54, (double[]){0.0, 0.36112240748271657, 0.3594957299715331, 0.0, 0.0, 0.0, 0.2793818625457503, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (2550.5)) {
                        if ((input[4]) <= (62.5)) {
                            memcpy(var54, (double[]){0.9825301204819277, 0.004819277108433735, 0.007228915662650603, 0.0030120481927710845, 0.0024096385542168677, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var54, (double[]){0.0, 0.041666666666666664, 0.2708333333333333, 0.5625, 0.125, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (13.5)) {
                            memcpy(var54, (double[]){0.00980392156862745, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9901960784313726, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var54, (double[]){0.9651567944250871, 0.0, 0.0, 0.0, 0.0, 0.0, 0.03484320557491289, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var54, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            memcpy(var54, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
        }
    } else {
        memcpy(var54, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var47, var54, 8, var46);
    double var55[8];
    if ((input[2]) <= (85.08427047729492)) {
        if ((input[7]) <= (0.8098421096801758)) {
            if ((input[13]) <= (0.851648360490799)) {
                if ((input[12]) <= (0.5565217286348343)) {
                    if ((input[8]) <= (0.395303338766098)) {
                        if ((input[1]) <= (4144.5)) {
                            memcpy(var55, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.015965166908563134, 0.02539912917271408, 0.6937590711175616, 0.001451378809869376, 0.0, 0.0, 0.17779390420899854, 0.08563134978229318}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (15.5)) {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.9510869565217391, 0.0, 0.0, 0.04891304347826087}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[1]) <= (72702.0)) {
                    if ((input[5]) <= (1258.0)) {
                        if ((input[9]) <= (0.4800868860911578)) {
                            memcpy(var55, (double[]){0.05970149253731343, 0.7761194029850746, 0.0, 0.0, 0.11194029850746269, 0.0, 0.0, 0.05223880597014925}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[13]) <= (15.054534435272217)) {
                        if ((input[3]) <= (0.8828135430812836)) {
                            memcpy(var55, (double[]){0.0, 0.7428571428571429, 0.0, 0.0, 0.2571428571428571, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.0, 0.9855072463768116, 0.0, 0.0, 0.014492753623188406, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (473135.5)) {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.0, 0.9464285714285714, 0.0, 0.0, 0.05357142857142857, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[7]) <= (0.9816763699054718)) {
                if ((input[10]) <= (0.4163497984409332)) {
                    if ((input[13]) <= (0.6228070259094238)) {
                        if ((input[1]) <= (2718.0)) {
                            memcpy(var55, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var55, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[5]) <= (0.5)) {
                    memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                } else {
                    if ((input[1]) <= (74601.0)) {
                        if ((input[4]) <= (44.5)) {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.10975609756097561, 0.0, 0.0, 0.0, 0.8902439024390244}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var55, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    } else {
        if ((input[4]) <= (117.5)) {
            if ((input[1]) <= (1240086.0)) {
                if ((input[8]) <= (0.12134403735399246)) {
                    if ((input[6]) <= (0.9413406550884247)) {
                        if ((input[10]) <= (0.11026463657617569)) {
                            memcpy(var55, (double[]){0.9767666989351403, 0.0, 0.000968054211035818, 0.017424975798644726, 0.0, 0.0, 0.00484027105517909, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (1486.5)) {
                            memcpy(var55, (double[]){0.22519083969465647, 0.011450381679389313, 0.019083969465648856, 0.0, 0.0, 0.0, 0.183206106870229, 0.5610687022900763}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.9743589743589743, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.02564102564102564}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[10]) <= (0.13105924427509308)) {
                        if ((input[1]) <= (50399.0)) {
                            memcpy(var55, (double[]){0.5454545454545454, 0.0, 0.0, 0.0, 0.45454545454545453, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[3]) <= (722.91015625)) {
                    if ((input[10]) <= (0.06856539845466614)) {
                        if ((input[13]) <= (0.06292721815407276)) {
                            memcpy(var55, (double[]){0.997364953886693, 0.002635046113306983, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var55, (double[]){0.9685863874345549, 0.0, 0.0, 0.0, 0.0, 0.0, 0.031413612565445025, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[3]) <= (201.4284210205078)) {
                memcpy(var55, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[3]) <= (607.1764526367188)) {
                    if ((input[8]) <= (0.14801864326000214)) {
                        memcpy(var55, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var55, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var55, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var46, var55, 8, var45);
    double var56[8];
    if ((input[0]) <= (125.5)) {
        if ((input[0]) <= (102.5)) {
            memcpy(var56, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
        } else {
            if ((input[10]) <= (0.39320388436317444)) {
                if ((input[13]) <= (0.17142857611179352)) {
                    memcpy(var56, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[5]) <= (22.5)) {
                        if ((input[3]) <= (423.68804931640625)) {
                            memcpy(var56, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var56, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var56, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var56, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[1]) <= (2939374.5)) {
            if ((input[6]) <= (0.8896012604236603)) {
                if ((input[8]) <= (0.2641761302947998)) {
                    if ((input[0]) <= (2103.0)) {
                        if ((input[2]) <= (51.80622482299805)) {
                            memcpy(var56, (double[]){0.0, 0.0, 0.0, 0.27530364372469635, 0.0, 0.7246963562753036, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var56, (double[]){0.4256243213897937, 0.0, 0.0, 0.21932681867535286, 0.0, 0.016286644951140065, 0.002171552660152009, 0.33659066232356133}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (4897.0)) {
                            memcpy(var56, (double[]){0.3619402985074627, 0.0, 0.0, 0.6380597014925373, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var56, (double[]){0.004672897196261682, 0.0, 0.0, 0.9953271028037384, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[0]) <= (757.0)) {
                        if ((input[2]) <= (51.36353302001953)) {
                            memcpy(var56, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var56, (double[]){0.0, 0.0, 0.0, 0.0, 0.1383399209486166, 0.0, 0.0, 0.8616600790513834}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (15.5)) {
                            memcpy(var56, (double[]){0.0, 0.0, 0.0, 0.0, 0.9482551143200962, 0.0, 0.0, 0.05174488567990373}, 8 * sizeof(double));
                        } else {
                            memcpy(var56, (double[]){0.0, 0.0, 0.0, 0.0, 0.125, 0.0, 0.0, 0.875}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[5]) <= (2450.5)) {
                    if ((input[13]) <= (0.1671842709183693)) {
                        if ((input[2]) <= (51.21347618103027)) {
                            memcpy(var56, (double[]){0.0, 0.036556603773584904, 0.9634433962264151, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var56, (double[]){0.41187384044526903, 0.0055658627087198514, 0.04638218923933209, 0.0, 0.0, 0.0, 0.0, 0.536178107606679}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (589.0)) {
                            memcpy(var56, (double[]){0.0, 0.36363636363636365, 0.0, 0.0, 0.0, 0.0, 0.0, 0.6363636363636364}, 8 * sizeof(double));
                        } else {
                            memcpy(var56, (double[]){0.0, 0.9961880559085133, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0038119440914866584}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var56, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[5]) <= (7.0)) {
                if ((input[1]) <= (7129832.0)) {
                    memcpy(var56, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var56, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (1234.067138671875)) {
                    memcpy(var56, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[6]) <= (0.9581229388713837)) {
                        memcpy(var56, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var56, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    }
    add_vectors(var45, var56, 8, var44);
    double var57[8];
    if ((input[0]) <= (125.5)) {
        if ((input[8]) <= (0.6364809274673462)) {
            if ((input[10]) <= (0.40163934230804443)) {
                if ((input[12]) <= (0.23492063581943512)) {
                    memcpy(var57, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[12]) <= (0.24880952388048172)) {
                        memcpy(var57, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var57, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var57, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        } else {
            memcpy(var57, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[8]) <= (0.2649088054895401)) {
            if ((input[10]) <= (0.04062318056821823)) {
                if ((input[6]) <= (0.8927757740020752)) {
                    if ((input[2]) <= (121.4632797241211)) {
                        if ((input[9]) <= (0.39619248546659946)) {
                            memcpy(var57, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var57, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (118.5)) {
                            memcpy(var57, (double[]){0.9802130898021308, 0.0, 0.0, 0.0106544901065449, 0.0015220700152207, 0.0076103500761035, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var57, (double[]){0.11764705882352941, 0.0, 0.0, 0.8823529411764706, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (126.85255813598633)) {
                        if ((input[1]) <= (65975.0)) {
                            memcpy(var57, (double[]){0.000992063492063492, 0.07341269841269842, 0.3323412698412698, 0.0, 0.0, 0.0, 0.5932539682539683, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var57, (double[]){0.02676864244741874, 0.550031867431485, 0.3505417463352454, 0.0, 0.0, 0.0, 0.07265774378585087, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (1470.5)) {
                            memcpy(var57, (double[]){0.7283950617283951, 0.037037037037037035, 0.012345679012345678, 0.0, 0.0, 0.0, 0.2222222222222222, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var57, (double[]){0.99055330634278, 0.002699055330634278, 0.0, 0.0, 0.0, 0.0, 0.006747638326585695, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var57, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[10]) <= (0.1427600234746933)) {
                memcpy(var57, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                memcpy(var57, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var44, var57, 8, var43);
    double var58[8];
    if ((input[0]) <= (129.5)) {
        if ((input[8]) <= (0.6732456237077713)) {
            if ((input[13]) <= (0.15833333879709244)) {
                if ((input[2]) <= (786.3443298339844)) {
                    if ((input[1]) <= (71707.5)) {
                        if ((input[2]) <= (67.24067687988281)) {
                            memcpy(var58, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.996661101836394, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.00333889816360601}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.41295502334833145)) {
                            memcpy(var58, (double[]){0.3333333333333333, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.6666666666666666}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (926.6531677246094)) {
                        memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var58, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[9]) <= (0.01904761977493763)) {
                    if ((input[10]) <= (0.3857142925262451)) {
                        if ((input[1]) <= (22024.5)) {
                            memcpy(var58, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.8333333333333334, 0.0, 0.16666666666666666, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var58, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[13]) <= (0.904840499162674)) {
            if ((input[2]) <= (127.20758438110352)) {
                if ((input[9]) <= (0.39727040566504)) {
                    if ((input[8]) <= (0.3093525171279907)) {
                        if ((input[3]) <= (124.16551971435547)) {
                            memcpy(var58, (double[]){0.0014012143858010276, 0.01914992993928071, 0.390471742176553, 0.3657169546940682, 0.0, 0.0, 0.10462400747314339, 0.11863615133115367}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.29559748427672955, 0.0, 0.025157232704402517, 0.13836477987421383, 0.0, 0.0, 0.3018867924528302, 0.2389937106918239}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.39085546135902405)) {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[5]) <= (15.5)) {
                    if ((input[10]) <= (0.16251353919506073)) {
                        if ((input[3]) <= (168.9172706604004)) {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.22950819672131148, 0.040983606557377046, 0.040983606557377046, 0.0, 0.680327868852459, 0.00819672131147541, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[10]) <= (0.0609900988638401)) {
                        if ((input[4]) <= (267.5)) {
                            memcpy(var58, (double[]){0.9837157660991858, 0.0, 0.0, 0.0, 0.0, 0.0014803849000740192, 0.014803849000740192, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[13]) <= (3.706723928451538)) {
                if ((input[8]) <= (0.35869525151792914)) {
                    if ((input[0]) <= (486.5)) {
                        if ((input[10]) <= (0.4677914083003998)) {
                            memcpy(var58, (double[]){0.15254237288135594, 0.0, 0.0, 0.13559322033898305, 0.0, 0.11864406779661017, 0.5932203389830508, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.4998346008360386)) {
                            memcpy(var58, (double[]){0.5454545454545454, 0.0, 0.0, 0.3977272727272727, 0.0, 0.056818181818181816, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.0, 0.9988109393579072, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0011890606420927466}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[7]) <= (0.010425307787954807)) {
                        memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[5]) <= (5.5)) {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.5}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[1]) <= (302607.5)) {
                    if ((input[3]) <= (350.0967254638672)) {
                        if ((input[6]) <= (0.4565259525552392)) {
                            memcpy(var58, (double[]){0.30303030303030304, 0.0, 0.0, 0.21212121212121213, 0.12121212121212122, 0.0, 0.0, 0.36363636363636365}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (249504.5)) {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[6]) <= (0.9972313046455383)) {
                        if ((input[10]) <= (0.2271309792995453)) {
                            memcpy(var58, (double[]){0.6666666666666666, 0.0, 0.0, 0.20833333333333334, 0.125, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (397.41576194763184)) {
                            memcpy(var58, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var58, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    }
    add_vectors(var43, var58, 8, var42);
    double var59[8];
    if ((input[10]) <= (0.04062318056821823)) {
        if ((input[2]) <= (110.45717239379883)) {
            if ((input[0]) <= (124.5)) {
                memcpy(var59, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[2]) <= (39.814443588256836)) {
                    if ((input[8]) <= (0.4408228697720915)) {
                        if ((input[4]) <= (47.0)) {
                            memcpy(var59, (double[]){0.0, 0.0, 0.0, 0.1091314031180401, 0.0, 0.888641425389755, 0.0022271714922048997, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var59, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var59, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[2]) <= (40.968868255615234)) {
                        if ((input[5]) <= (1254.5)) {
                            memcpy(var59, (double[]){0.0, 0.10971428571428571, 0.8788571428571429, 0.004571428571428572, 0.004571428571428572, 0.002285714285714286, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var59, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.6360623240470886)) {
                            memcpy(var59, (double[]){0.0, 0.0, 0.0, 0.7208029197080292, 0.2427007299270073, 0.0364963503649635, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var59, (double[]){0.022957461174881837, 0.5557056043214045, 0.08777852802160702, 0.0, 0.0, 0.0, 0.33355840648210666, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[4]) <= (118.5)) {
                if ((input[9]) <= (0.026984128169715405)) {
                    if ((input[5]) <= (8.5)) {
                        if ((input[5]) <= (4.5)) {
                            memcpy(var59, (double[]){0.7708333333333334, 0.027777777777777776, 0.020833333333333332, 0.05555555555555555, 0.125, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var59, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (4032.5)) {
                            memcpy(var59, (double[]){0.9911452184179457, 0.0011806375442739079, 0.0023612750885478157, 0.0, 0.004132231404958678, 0.0, 0.0011806375442739079, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var59, (double[]){0.8154761904761905, 0.0, 0.0, 0.0, 0.0, 0.0, 0.18452380952380953, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[0]) <= (414.0)) {
                        memcpy(var59, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var59, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[8]) <= (0.13384956121444702)) {
                    if ((input[6]) <= (0.0019376646960154176)) {
                        memcpy(var59, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[6]) <= (0.0025446126237511635)) {
                            memcpy(var59, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var59, (double[]){0.1, 0.0, 0.0, 0.9, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var59, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        memcpy(var59, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var42, var59, 8, var41);
    double var60[8];
    if ((input[10]) <= (0.05718035250902176)) {
        if ((input[2]) <= (86.50704574584961)) {
            if ((input[6]) <= (0.8516281545162201)) {
                if ((input[7]) <= (0.869636058807373)) {
                    if ((input[0]) <= (103.0)) {
                        memcpy(var60, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[4]) <= (48.0)) {
                            memcpy(var60, (double[]){0.0, 0.0, 0.0, 0.0, 0.4479025710419486, 0.5520974289580515, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var60, (double[]){0.0, 0.0, 0.0, 0.007042253521126761, 0.9929577464788732, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var60, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[4]) <= (21.5)) {
                    if ((input[7]) <= (0.008260383736342192)) {
                        if ((input[13]) <= (2.622129440307617)) {
                            memcpy(var60, (double[]){0.05004812319538017, 0.3320500481231954, 0.3734359961501444, 0.0, 0.0, 0.0, 0.24446583253128007, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var60, (double[]){0.007874015748031496, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9921259842519685, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (1325.0)) {
                            memcpy(var60, (double[]){0.125, 0.2916666666666667, 0.5833333333333334, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var60, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[13]) <= (0.5350552536547184)) {
                        memcpy(var60, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var60, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[2]) <= (148.851318359375)) {
                if ((input[4]) <= (11.5)) {
                    if ((input[5]) <= (1712.5)) {
                        if ((input[0]) <= (526.0)) {
                            memcpy(var60, (double[]){0.9963768115942029, 0.0, 0.0036231884057971015, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var60, (double[]){0.5306122448979592, 0.0, 0.0, 0.0, 0.46938775510204084, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var60, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[8]) <= (0.3093525171279907)) {
                        memcpy(var60, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var60, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[4]) <= (148.5)) {
                    if ((input[2]) <= (308.2916717529297)) {
                        if ((input[3]) <= (376.49281311035156)) {
                            memcpy(var60, (double[]){0.9822784810126582, 0.0, 0.005063291139240506, 0.0, 0.007594936708860759, 0.002531645569620253, 0.002531645569620253, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var60, (double[]){0.6666666666666666, 0.017543859649122806, 0.008771929824561403, 0.0, 0.2807017543859649, 0.008771929824561403, 0.017543859649122806, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[8]) <= (0.09139171004062518)) {
                            memcpy(var60, (double[]){0.9854227405247813, 0.004373177842565598, 0.0, 0.0, 0.0, 0.0, 0.01020408163265306, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var60, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[4]) <= (1175.0)) {
                        if ((input[3]) <= (214.54675674438477)) {
                            memcpy(var60, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var60, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var60, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    } else {
        memcpy(var60, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var41, var60, 8, var40);
    double var61[8];
    if ((input[13]) <= (0.8354564607143402)) {
        if ((input[0]) <= (127.5)) {
            if ((input[1]) <= (72115.5)) {
                if ((input[13]) <= (0.5833333432674408)) {
                    if ((input[9]) <= (0.026984128169715405)) {
                        if ((input[1]) <= (9429.0)) {
                            memcpy(var61, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.9892857142857143, 0.0, 0.0, 0.0035714285714285713, 0.0, 0.0, 0.0, 0.007142857142857143}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[9]) <= (0.07167919911444187)) {
                            memcpy(var61, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[6]) <= (0.03953942283987999)) {
                        memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var61, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[3]) <= (590.93115234375)) {
                    if ((input[10]) <= (0.4128440320491791)) {
                        memcpy(var61, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var61, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[2]) <= (149.97498321533203)) {
                if ((input[7]) <= (0.381180003285408)) {
                    if ((input[2]) <= (39.852853775024414)) {
                        if ((input[8]) <= (0.43768682703375816)) {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.9969040247678018, 0.0030959752321981426, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (47.53348731994629)) {
                            memcpy(var61, (double[]){0.0, 0.03095684803001876, 0.7636022514071295, 0.0, 0.01594746716697936, 0.009380863039399626, 0.1801125703564728, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.13304721030042918, 0.0, 0.07296137339055794, 0.0, 0.24248927038626608, 0.045064377682403435, 0.12660944206008584, 0.3798283261802575}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (15.0)) {
                        if ((input[10]) <= (0.4544117748737335)) {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (57098.5)) {
                            memcpy(var61, (double[]){0.6818181818181818, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.3181818181818182}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.0625, 0.0, 0.0, 0.0625, 0.0, 0.0, 0.0, 0.875}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[0]) <= (1502.5)) {
                    if ((input[10]) <= (0.11026463657617569)) {
                        if ((input[6]) <= (0.998651385307312)) {
                            memcpy(var61, (double[]){0.8577878103837472, 0.0, 0.002257336343115124, 0.002257336343115124, 0.12866817155756208, 0.006772009029345372, 0.002257336343115124, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.4782608695652174, 0.17391304347826086, 0.043478260869565216, 0.0, 0.0, 0.0, 0.30434782608695654, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[1]) <= (622900.0)) {
                        if ((input[8]) <= (0.25351009040605277)) {
                            memcpy(var61, (double[]){0.9, 0.0, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.04062318056821823)) {
                            memcpy(var61, (double[]){0.9852476290832455, 0.004214963119072708, 0.0, 0.0, 0.001053740779768177, 0.0, 0.009483667017913594, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    } else {
        if ((input[5]) <= (1394.5)) {
            if ((input[13]) <= (24434.7646484375)) {
                if ((input[6]) <= (0.5309142023324966)) {
                    if ((input[9]) <= (0.4824315635487437)) {
                        if ((input[5]) <= (20.5)) {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.46601941747572817, 0.42718446601941745, 0.0, 0.0, 0.10679611650485436}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[1]) <= (26175.5)) {
                        if ((input[10]) <= (0.48787879943847656)) {
                            memcpy(var61, (double[]){0.8, 0.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (417.3024482727051)) {
                            memcpy(var61, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[0]) <= (37471.0)) {
                    if ((input[4]) <= (4.5)) {
                        if ((input[2]) <= (421.0810546875)) {
                            memcpy(var61, (double[]){0.22727272727272727, 0.0, 0.0, 0.18181818181818182, 0.0, 0.09090909090909091, 0.0, 0.5}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){0.034482758620689655, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9655172413793104}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (67.85213387012482)) {
                            memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var61, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var61, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[1]) <= (3656415.5)) {
                memcpy(var61, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
            } else {
                memcpy(var61, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var40, var61, 8, var39);
    double var62[8];
    if ((input[0]) <= (126.5)) {
        if ((input[2]) <= (641.1368408203125)) {
            if ((input[4]) <= (28.0)) {
                if ((input[2]) <= (67.38479614257812)) {
                    memcpy(var62, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[2]) <= (68.78588485717773)) {
                        memcpy(var62, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        if ((input[10]) <= (0.3857142925262451)) {
                            memcpy(var62, (double[]){0.9969604863221885, 0.0, 0.00303951367781155, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var62, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var62, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[7]) <= (0.0972906444221735)) {
                if ((input[3]) <= (525.1617889404297)) {
                    memcpy(var62, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                } else {
                    memcpy(var62, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (761.6218872070312)) {
                    if ((input[12]) <= (0.019736841320991516)) {
                        memcpy(var62, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var62, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var62, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[9]) <= (0.27980017103254795)) {
                if ((input[13]) <= (0.904840499162674)) {
                    if ((input[2]) <= (149.02095794677734)) {
                        if ((input[4]) <= (18910.0)) {
                            memcpy(var62, (double[]){0.03642384105960265, 0.013245033112582781, 0.24613686534216336, 0.3127299484915379, 0.2862398822663723, 0.0, 0.10522442972774099, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var62, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (3046.5)) {
                            memcpy(var62, (double[]){0.8041958041958042, 0.008741258741258742, 0.0034965034965034965, 0.006993006993006993, 0.1346153846153846, 0.0, 0.04195804195804196, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var62, (double[]){0.9975874547647768, 0.0, 0.0, 0.0, 0.0012062726176115801, 0.0, 0.0012062726176115801, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[6]) <= (0.48759330809116364)) {
                        if ((input[1]) <= (2482720.5)) {
                            memcpy(var62, (double[]){0.29770992366412213, 0.0, 0.0, 0.4351145038167939, 0.26717557251908397, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var62, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (31.836440086364746)) {
                            memcpy(var62, (double[]){0.0, 0.6977351916376306, 0.0, 0.0, 0.0, 0.0, 0.30226480836236935, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var62, (double[]){0.0, 0.3333333333333333, 0.0, 0.0, 0.0, 0.0, 0.6666666666666666, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var62, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            memcpy(var62, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    }
    add_vectors(var39, var62, 8, var38);
    double var63[8];
    if ((input[8]) <= (0.12320279330015182)) {
        if ((input[10]) <= (0.05718035250902176)) {
            if ((input[0]) <= (152.5)) {
                if ((input[9]) <= (0.5426978096365929)) {
                    if ((input[6]) <= (0.9886363744735718)) {
                        memcpy(var63, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[4]) <= (37.0)) {
                            memcpy(var63, (double[]){0.9574468085106383, 0.02127659574468085, 0.02127659574468085, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[0]) <= (234.5)) {
                    if ((input[7]) <= (0.15560975670814514)) {
                        if ((input[12]) <= (0.409406341612339)) {
                            memcpy(var63, (double[]){0.02869757174392936, 0.002207505518763797, 0.10816777041942605, 0.0, 0.0, 0.0, 0.8609271523178808, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (10.5)) {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (150.1121597290039)) {
                        if ((input[13]) <= (0.8918439745903015)) {
                            memcpy(var63, (double[]){0.045736064792758456, 0.016198189614101955, 0.3830395426393521, 0.39399714149595044, 0.0, 0.14530728918532634, 0.01572177227251072, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){0.0007627765064836003, 0.7246376811594203, 0.0, 0.04500381388253242, 0.0, 0.005339435545385202, 0.2242562929061785, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (520.5)) {
                            memcpy(var63, (double[]){0.969558599695586, 0.00228310502283105, 0.00228310502283105, 0.0015220700152207, 0.0, 0.00380517503805175, 0.02054794520547945, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[3]) <= (409.0496368408203)) {
            if ((input[4]) <= (3.5)) {
                if ((input[2]) <= (50.542640686035156)) {
                    memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[0]) <= (654.0)) {
                        memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[1]) <= (51930.5)) {
                    if ((input[4]) <= (6.5)) {
                        if ((input[6]) <= (0.044904692098498344)) {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.88, 0.0, 0.0, 0.12}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){0.09523809523809523, 0.0, 0.0, 0.0, 0.14285714285714285, 0.0, 0.0, 0.7619047619047619}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (48102.5)) {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.991869918699187, 0.0, 0.0, 0.008130081300813009}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[4]) <= (48.0)) {
                if ((input[1]) <= (71586.0)) {
                    if ((input[6]) <= (0.24928670935332775)) {
                        memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[7]) <= (0.254841573536396)) {
                        if ((input[8]) <= (0.2887369990348816)) {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.011363636363636364, 0.0, 0.0, 0.9886363636363636}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.13105924427509308)) {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var63, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var38, var63, 8, var37);
    double var64[8];
    if ((input[2]) <= (86.50499725341797)) {
        if ((input[5]) <= (1562.5)) {
            if ((input[13]) <= (0.8756542503833771)) {
                if ((input[6]) <= (0.8974432945251465)) {
                    if ((input[0]) <= (123.5)) {
                        memcpy(var64, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[8]) <= (0.3973737321794033)) {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.6059390048154093, 0.0, 0.29614767255216695, 0.0, 0.09791332263242375}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 0.9477401129943502, 0.0, 0.0, 0.052259887005649715}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[13]) <= (0.04342605546116829)) {
                        if ((input[6]) <= (0.9912068843841553)) {
                            memcpy(var64, (double[]){0.029411764705882353, 0.0, 0.5441176470588235, 0.0, 0.0, 0.0, 0.0, 0.4264705882352941}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.03609756097560975, 0.03414634146341464, 0.8517073170731707, 0.0, 0.0, 0.0, 0.0, 0.07804878048780488}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (2043.5)) {
                            memcpy(var64, (double[]){0.2, 0.0, 0.06666666666666667, 0.0, 0.0, 0.0, 0.0, 0.7333333333333333}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[6]) <= (0.9532510638237)) {
                    if ((input[12]) <= (0.5101033076643944)) {
                        if ((input[7]) <= (0.9204280972480774)) {
                            memcpy(var64, (double[]){0.017543859649122806, 0.0, 0.0, 0.0, 0.7719298245614035, 0.0, 0.0, 0.21052631578947367}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (0.0026761703193187714)) {
                        if ((input[13]) <= (2.0)) {
                            memcpy(var64, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.25, 0.75, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.9827347099781036)) {
                            memcpy(var64, (double[]){0.0, 0.625, 0.0, 0.0, 0.0, 0.0, 0.0, 0.375}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[6]) <= (0.034398242831230164)) {
            if ((input[10]) <= (0.2271309792995453)) {
                if ((input[3]) <= (21.888046264648438)) {
                    if ((input[2]) <= (121.87179565429688)) {
                        memcpy(var64, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[1]) <= (19360.0)) {
                            memcpy(var64, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[1]) <= (658417.5)) {
                        if ((input[7]) <= (0.8706125319004059)) {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.9839142091152815, 0.0, 0.0, 0.0160857908847185, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.8056367635726929)) {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[10]) <= (0.04062318056821823)) {
                if ((input[13]) <= (0.7534153163433075)) {
                    if ((input[13]) <= (0.016029618680477142)) {
                        if ((input[4]) <= (62.5)) {
                            memcpy(var64, (double[]){0.9889267461669506, 0.0034071550255536627, 0.0008517887563884157, 0.0, 0.00596252129471891, 0.0, 0.0008517887563884157, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[8]) <= (0.3184361010789871)) {
                            memcpy(var64, (double[]){0.8427299703264095, 0.002967359050445104, 0.026706231454005934, 0.026706231454005934, 0.0, 0.011869436201780416, 0.08902077151335312, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[3]) <= (129.91167449951172)) {
                        memcpy(var64, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[5]) <= (1424.0)) {
                            memcpy(var64, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var64, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var37, var64, 8, var36);
    double var65[8];
    if ((input[2]) <= (110.31181335449219)) {
        if ((input[6]) <= (0.8835224807262421)) {
            if ((input[9]) <= (0.47132131457328796)) {
                if ((input[1]) <= (4360.0)) {
                    memcpy(var65, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[4]) <= (16024.0)) {
                        if ((input[4]) <= (2721.0)) {
                            memcpy(var65, (double[]){0.002708192281651997, 0.0, 0.0, 0.46716316858496953, 0.4014895057549086, 0.0, 0.0, 0.12863913337846988}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.07234042553191489, 0.9276595744680851, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var65, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[6]) <= (0.9969525039196014)) {
                if ((input[0]) <= (234.5)) {
                    if ((input[1]) <= (7633.0)) {
                        if ((input[0]) <= (117.5)) {
                            memcpy(var65, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.45483872294425964)) {
                            memcpy(var65, (double[]){0.009708737864077669, 0.0, 0.02912621359223301, 0.0, 0.0, 0.0, 0.9611650485436893, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[10]) <= (0.42204898595809937)) {
                        if ((input[1]) <= (42836.0)) {
                            memcpy(var65, (double[]){0.0, 0.013157894736842105, 0.8026315789473685, 0.0, 0.0, 0.0, 0.18421052631578946, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.5454545454545454, 0.15584415584415584, 0.0, 0.0, 0.0, 0.2987012987012987, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[0]) <= (1647.5)) {
                    if ((input[13]) <= (1.3088849186897278)) {
                        if ((input[5]) <= (1282.0)) {
                            memcpy(var65, (double[]){0.033632286995515695, 0.21300448430493274, 0.6098654708520179, 0.0, 0.0, 0.0, 0.0, 0.14349775784753363}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (0.19801980257034302)) {
                            memcpy(var65, (double[]){0.030303030303030304, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9696969696969697, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0036900369003690036, 0.0, 0.0, 0.0, 0.0, 0.996309963099631, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (40.0)) {
                        if ((input[13]) <= (0.07602832932025194)) {
                            memcpy(var65, (double[]){0.0, 0.041121495327102804, 0.9588785046728971, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (5071.5)) {
                            memcpy(var65, (double[]){0.8222222222222222, 0.0, 0.0, 0.0, 0.0, 0.0, 0.17777777777777778, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    } else {
        if ((input[8]) <= (0.18210437893867493)) {
            if ((input[5]) <= (3.5)) {
                if ((input[4]) <= (43.5)) {
                    if ((input[12]) <= (0.0714285746216774)) {
                        if ((input[0]) <= (1750.5)) {
                            memcpy(var65, (double[]){0.025210084033613446, 0.008403361344537815, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9663865546218487}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.75, 0.25, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var65, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[4]) <= (118.0)) {
                        if ((input[7]) <= (0.5)) {
                            memcpy(var65, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var65, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[2]) <= (721.590576171875)) {
                    if ((input[4]) <= (122.0)) {
                        if ((input[10]) <= (0.1453765481710434)) {
                            memcpy(var65, (double[]){0.9699510831586303, 0.0020964360587002098, 0.0006988120195667365, 0.0006988120195667365, 0.0, 0.001397624039133473, 0.025157232704402517, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (376.8486557006836)) {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[10]) <= (0.04062318056821823)) {
                        if ((input[5]) <= (5852.5)) {
                            memcpy(var65, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[7]) <= (0.09095893427729607)) {
                if ((input[4]) <= (86.5)) {
                    if ((input[8]) <= (0.6340588331222534)) {
                        if ((input[13]) <= (0.003105590119957924)) {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[4]) <= (50.0)) {
                    if ((input[5]) <= (18.5)) {
                        if ((input[4]) <= (3.5)) {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.14285714285714285, 0.0, 0.0, 0.8571428571428571}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){0.018867924528301886, 0.0, 0.0, 0.0, 0.9622641509433962, 0.0, 0.0, 0.018867924528301886}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[12]) <= (0.02380952425301075)) {
                            memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var65, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var65, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var36, var65, 8, var35);
    double var66[8];
    if ((input[5]) <= (15.5)) {
        if ((input[0]) <= (108.0)) {
            if ((input[4]) <= (2.5)) {
                memcpy(var66, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[10]) <= (0.39320388436317444)) {
                    memcpy(var66, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[8]) <= (0.10728539898991585)) {
                if ((input[7]) <= (0.6689157783985138)) {
                    if ((input[9]) <= (0.33237103279680014)) {
                        if ((input[2]) <= (40.968082427978516)) {
                            memcpy(var66, (double[]){0.0, 0.12659698025551683, 0.8734030197444832, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.026424442609413706, 0.708505367464905, 0.08422791081750619, 0.0, 0.0, 0.0, 0.0, 0.18084227910817507}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[2]) <= (274.92076110839844)) {
                        if ((input[4]) <= (3.5)) {
                            memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.6124401913875598, 0.0, 0.0, 0.0, 0.3875598086124402}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.9973614775725593, 0.0, 0.0, 0.0, 0.002638522427440633}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (380.3219299316406)) {
                            memcpy(var66, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.045454545454545456, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9545454545454546}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[5]) <= (1.5)) {
                    if ((input[2]) <= (44.48871040344238)) {
                        memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[6]) <= (0.23029934242367744)) {
                            memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (595.858642578125)) {
                        if ((input[5]) <= (8.5)) {
                            memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.9908536585365854, 0.0, 0.0, 0.009146341463414634}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.014285714285714285, 0.0, 0.0, 0.0, 0.9, 0.0, 0.0, 0.08571428571428572}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    } else {
        if ((input[1]) <= (387317.0)) {
            if ((input[0]) <= (199.0)) {
                if ((input[0]) <= (130.5)) {
                    if ((input[13]) <= (0.15833333879709244)) {
                        if ((input[0]) <= (121.5)) {
                            memcpy(var66, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.9230769230769231, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.07692307692307693}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (101.0)) {
                            memcpy(var66, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.875, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.125}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[12]) <= (0.033929421566426754)) {
                        if ((input[7]) <= (0.7618945837020874)) {
                            memcpy(var66, (double[]){0.6666666666666666, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.3333333333333333}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.92, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.08}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.4881048146635294)) {
                            memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[5]) <= (2090.5)) {
                    if ((input[0]) <= (311.5)) {
                        if ((input[7]) <= (0.021639129612594843)) {
                            memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.9552238805970149, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.04477611940298507}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (43089.0)) {
                            memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0196078431372549, 0.0, 0.9803921568627451}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.577922077922078, 0.0, 0.006493506493506494, 0.0, 0.003246753246753247, 0.003246753246753247, 0.0, 0.4090909090909091}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[6]) <= (0.5415588021278381)) {
                        memcpy(var66, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[10]) <= (0.05718035250902176)) {
                if ((input[4]) <= (173.0)) {
                    if ((input[1]) <= (1871973.0)) {
                        if ((input[2]) <= (602.6895446777344)) {
                            memcpy(var66, (double[]){0.9946236559139785, 0.0, 0.0, 0.0, 0.0, 0.0, 0.005376344086021506, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var66, (double[]){0.8181818181818182, 0.0, 0.0, 0.0, 0.0, 0.0, 0.18181818181818182, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var66, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[12]) <= (0.00003401129288249649)) {
                        memcpy(var66, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var66, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var35, var66, 8, var34);
    double var67[8];
    if ((input[5]) <= (15.5)) {
        if ((input[8]) <= (0.09250359260477126)) {
            if ((input[1]) <= (4910.5)) {
                if ((input[9]) <= (0.6307692229747772)) {
                    if ((input[4]) <= (45.5)) {
                        memcpy(var67, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var67, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[13]) <= (0.8692439794540405)) {
                    if ((input[2]) <= (51.74760627746582)) {
                        if ((input[12]) <= (0.3841460347175598)) {
                            memcpy(var67, (double[]){0.0, 0.030115830115830116, 0.6517374517374518, 0.31814671814671813, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[12]) <= (0.000013808721632813103)) {
                            memcpy(var67, (double[]){0.17237687366167023, 0.007494646680942184, 0.017130620985010708, 0.37044967880085655, 0.0, 0.0, 0.0, 0.43254817987152033}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.05154639175257732, 0.0, 0.14432989690721648, 0.7319587628865979, 0.0, 0.07216494845360824, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[7]) <= (0.037484319880604744)) {
                        if ((input[2]) <= (34.180702209472656)) {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.0, 0.9899328859060402, 0.0, 0.0, 0.0, 0.0, 0.0, 0.010067114093959731}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (83.04537582397461)) {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.9365079365079365, 0.0, 0.0, 0.0, 0.06349206349206349}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.2222222222222222, 0.0, 0.0, 0.0, 0.0, 0.16666666666666666, 0.0, 0.6111111111111112}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[4]) <= (3.5)) {
                if ((input[7]) <= (0.001401035871822387)) {
                    if ((input[6]) <= (0.002943438128568232)) {
                        if ((input[3]) <= (233.25637245178223)) {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.9423076923076923, 0.0, 0.0, 0.057692307692307696}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (650.5)) {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.12962962962962962, 0.0, 0.0, 0.8703703703703703}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (57.20950126647949)) {
                        memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[9]) <= (0.0009643201483413577)) {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[8]) <= (0.9888276159763336)) {
                    if ((input[10]) <= (0.4160839021205902)) {
                        memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[10]) <= (0.49593496322631836)) {
                        memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    } else {
        if ((input[4]) <= (3.5)) {
            if ((input[5]) <= (1538.0)) {
                if ((input[3]) <= (22.693939208984375)) {
                    memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                } else {
                    if ((input[1]) <= (80807.0)) {
                        if ((input[4]) <= (2.5)) {
                            memcpy(var67, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.9811320754716981, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.018867924528301886}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.30965909361839294)) {
                            memcpy(var67, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[13]) <= (3.172727346420288)) {
                if ((input[4]) <= (6.5)) {
                    if ((input[10]) <= (0.04062318056821823)) {
                        if ((input[7]) <= (0.10246031731367111)) {
                            memcpy(var67, (double[]){0.6301369863013698, 0.0, 0.0, 0.0, 0.0, 0.0, 0.3698630136986301, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[0]) <= (1482.0)) {
                        if ((input[2]) <= (648.2403564453125)) {
                            memcpy(var67, (double[]){0.782258064516129, 0.0, 0.0, 0.0, 0.008064516129032258, 0.005376344086021506, 0.12634408602150538, 0.07795698924731183}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.2125, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.7875}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (695.5)) {
                            memcpy(var67, (double[]){0.9820143884892086, 0.0, 0.002398081534772182, 0.0, 0.0, 0.0, 0.014388489208633094, 0.001199040767386091}, 8 * sizeof(double));
                        } else {
                            memcpy(var67, (double[]){0.0, 0.8, 0.0, 0.0, 0.2, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[6]) <= (0.5268954932689667)) {
                    memcpy(var67, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var67, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var34, var67, 8, var33);
    double var68[8];
    if ((input[2]) <= (110.31181335449219)) {
        if ((input[8]) <= (0.4809211492538452)) {
            if ((input[4]) <= (0.5)) {
                memcpy(var68, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[2]) <= (39.540096282958984)) {
                    if ((input[9]) <= (0.3621397032402456)) {
                        memcpy(var68, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[2]) <= (41.127458572387695)) {
                        if ((input[2]) <= (40.17406463623047)) {
                            memcpy(var68, (double[]){0.0022123893805309734, 0.08185840707964602, 0.7986725663716814, 0.0, 0.0, 0.0, 0.1172566371681416, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.011299435028248588, 0.13559322033898305, 0.5028248587570622, 0.022598870056497175, 0.0, 0.011299435028248588, 0.3163841807909605, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (51.515424728393555)) {
                            memcpy(var68, (double[]){0.005649717514124294, 0.5948345439870864, 0.06941081517352704, 0.002421307506053269, 0.0, 0.014527845036319613, 0.3131557707828894, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.16929133858267717, 0.04429133858267716, 0.024606299212598427, 0.3838582677165354, 0.0, 0.006889763779527559, 0.1309055118110236, 0.24015748031496062}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[5]) <= (15.5)) {
                if ((input[2]) <= (51.408599853515625)) {
                    memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[8]) <= (0.9587031900882721)) {
                        if ((input[13]) <= (0.4593406766653061)) {
                            memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.8, 0.0, 0.0, 0.2}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[0]) <= (740.5)) {
                    memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                } else {
                    memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        if ((input[1]) <= (1187019.0)) {
            if ((input[3]) <= (409.6968231201172)) {
                if ((input[8]) <= (0.4047619178891182)) {
                    if ((input[5]) <= (3.5)) {
                        if ((input[4]) <= (42.0)) {
                            memcpy(var68, (double[]){0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.0, 0.5}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.30921053886413574)) {
                            memcpy(var68, (double[]){0.9538077403245943, 0.0024968789013732834, 0.0, 0.01373283395755306, 0.0, 0.0024968789013732834, 0.02746566791510612, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[7]) <= (0.15395362675189972)) {
                        if ((input[0]) <= (1740.0)) {
                            memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[2]) <= (641.1029968261719)) {
                    if ((input[8]) <= (0.002680563891772181)) {
                        if ((input[2]) <= (179.84332275390625)) {
                            memcpy(var68, (double[]){0.08695652173913043, 0.0, 0.043478260869565216, 0.0, 0.0, 0.0, 0.0, 0.8695652173913043}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.8796296296296297, 0.0030864197530864196, 0.0, 0.0, 0.0, 0.0030864197530864196, 0.030864197530864196, 0.08333333333333333}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (33.5)) {
                            memcpy(var68, (double[]){0.0547945205479452, 0.0, 0.0, 0.0, 0.8356164383561644, 0.0, 0.0, 0.1095890410958904}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[4]) <= (13.5)) {
                        if ((input[3]) <= (571.3222351074219)) {
                            memcpy(var68, (double[]){0.007712082262210797, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9922879177377892}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.4017857142857143, 0.0, 0.0, 0.0, 0.0, 0.0, 0.017857142857142856, 0.5803571428571429}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var68, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[10]) <= (0.05718035250902176)) {
                if ((input[13]) <= (0.06363876909017563)) {
                    if ((input[4]) <= (2.5)) {
                        if ((input[6]) <= (0.9995841979980469)) {
                            memcpy(var68, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var68, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (666.8601379394531)) {
                        if ((input[4]) <= (18.5)) {
                            memcpy(var68, (double[]){0.9666666666666667, 0.0, 0.0, 0.0, 0.0, 0.0, 0.03333333333333333, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (7103.0)) {
                            memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var68, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var68, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var33, var68, 8, var32);
    double var69[8];
    if ((input[8]) <= (0.16184448450803757)) {
        if ((input[2]) <= (86.50499725341797)) {
            if ((input[13]) <= (0.8452380895614624)) {
                if ((input[6]) <= (0.8987787067890167)) {
                    if ((input[2]) <= (13.982586860656738)) {
                        memcpy(var69, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[5]) <= (0.5)) {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.8175675675675675, 0.0, 0.18243243243243243}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.03944954128440367, 0.0, 0.0, 0.6541284403669725, 0.0, 0.1981651376146789, 0.0009174311926605505, 0.10733944954128441}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (1378.0)) {
                        if ((input[2]) <= (51.21347618103027)) {
                            memcpy(var69, (double[]){0.008447729672650475, 0.042238648363252376, 0.9493136219640972, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.1921182266009852, 0.0, 0.1724137931034483, 0.0, 0.0, 0.0, 0.0, 0.6354679802955665}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[2]) <= (41.800851821899414)) {
                    if ((input[0]) <= (6952.0)) {
                        if ((input[4]) <= (79.5)) {
                            memcpy(var69, (double[]){0.0, 0.007782101167315175, 0.0, 0.0, 0.0, 0.03501945525291829, 0.9571984435797666, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.5002608592621982)) {
                            memcpy(var69, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (1282.0)) {
                        if ((input[1]) <= (26175.5)) {
                            memcpy(var69, (double[]){0.2, 0.1, 0.0, 0.2, 0.0, 0.0, 0.0, 0.5}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.97610513739546, 0.0, 0.021505376344086023, 0.0, 0.0023894862604540022, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[5]) <= (3.5)) {
                if ((input[7]) <= (0.9495233595371246)) {
                    if ((input[5]) <= (1.5)) {
                        if ((input[4]) <= (3.5)) {
                            memcpy(var69, (double[]){0.031746031746031744, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9682539682539683}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (2.5)) {
                            memcpy(var69, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.7142857142857143, 0.2857142857142857, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[12]) <= (0.0030303029343485832)) {
                        if ((input[2]) <= (426.4229202270508)) {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var69, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[0]) <= (1464.5)) {
                    if ((input[10]) <= (0.11026463657617569)) {
                        if ((input[4]) <= (35.5)) {
                            memcpy(var69, (double[]){0.9549218031278749, 0.0018399264029438822, 0.005519779208831647, 0.0, 0.0, 0.0009199632014719411, 0.03679852805887764, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.1, 0.0, 0.35, 0.55, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (192.71761322021484)) {
                        memcpy(var69, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[10]) <= (0.05718035250902176)) {
                            memcpy(var69, (double[]){0.9950347567030785, 0.0, 0.0, 0.0, 0.0, 0.0, 0.004965243296921549, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    } else {
        if ((input[0]) <= (757.0)) {
            if ((input[1]) <= (13534.0)) {
                if ((input[0]) <= (124.5)) {
                    memcpy(var69, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (532.8109893798828)) {
                    if ((input[0]) <= (281.0)) {
                        if ((input[4]) <= (46.0)) {
                            memcpy(var69, (double[]){0.6666666666666666, 0.0, 0.0, 0.0, 0.3333333333333333, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[8]) <= (0.8848001658916473)) {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.6666666666666666, 0.0, 0.0, 0.3333333333333333}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.05357142857142857, 0.0, 0.0, 0.9464285714285714}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[0]) <= (1497.0)) {
                if ((input[3]) <= (418.82334899902344)) {
                    memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[6]) <= (0.006571169476956129)) {
                        if ((input[10]) <= (0.2271309792995453)) {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (21.5)) {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.95, 0.0, 0.0, 0.05}, 8 * sizeof(double));
                        } else {
                            memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var69, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var32, var69, 8, var31);
    double var70[8];
    if ((input[10]) <= (0.05718035250902176)) {
        if ((input[5]) <= (15.5)) {
            if ((input[2]) <= (14.0)) {
                memcpy(var70, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[6]) <= (0.9105454683303833)) {
                    if ((input[9]) <= (0.44582758098840714)) {
                        if ((input[7]) <= (0.6995575129985809)) {
                            memcpy(var70, (double[]){0.03325942350332594, 0.0, 0.0022172949002217295, 0.0, 0.9645232815964523, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var70, (double[]){0.23157894736842105, 0.0, 0.0, 0.7640350877192983, 0.0043859649122807015, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var70, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (1.181578814983368)) {
                        if ((input[13]) <= (0.5046673850156367)) {
                            memcpy(var70, (double[]){0.005025125628140704, 0.038525963149078725, 0.9564489112227805, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var70, (double[]){0.05, 0.95, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[13]) <= (0.20084033906459808)) {
                            memcpy(var70, (double[]){0.15024630541871922, 0.04926108374384237, 0.8004926108374384, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var70, (double[]){0.0012121212121212121, 0.9987878787878788, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[2]) <= (74.57947158813477)) {
                if ((input[0]) <= (127.0)) {
                    memcpy(var70, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[5]) <= (1430.5)) {
                        if ((input[4]) <= (7296.0)) {
                            memcpy(var70, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var70, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var70, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[5]) <= (2652.5)) {
                    if ((input[5]) <= (2550.5)) {
                        if ((input[5]) <= (21.5)) {
                            memcpy(var70, (double[]){0.9935064935064936, 0.0, 0.0, 0.0, 0.006493506493506494, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var70, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (408.4336242675781)) {
                            memcpy(var70, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var70, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[13]) <= (1.1750493049621582)) {
                        if ((input[6]) <= (0.9999582171440125)) {
                            memcpy(var70, (double[]){0.9308943089430894, 0.0, 0.0, 0.0, 0.0, 0.0, 0.06910569105691057, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var70, (double[]){0.5909090909090909, 0.0, 0.0, 0.0, 0.0, 0.0, 0.4090909090909091, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (6401.0)) {
                            memcpy(var70, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var70, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    } else {
        memcpy(var70, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var31, var70, 8, var30);
    double var71[8];
    if ((input[5]) <= (15.5)) {
        if ((input[1]) <= (4768.0)) {
            if ((input[13]) <= (0.8333333432674408)) {
                if ((input[12]) <= (0.6810126751661301)) {
                    if ((input[7]) <= (0.9637705087661743)) {
                        memcpy(var71, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[6]) <= (0.00920245423913002)) {
                            memcpy(var71, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[9]) <= (0.34298195876181126)) {
                if ((input[6]) <= (0.8924852013587952)) {
                    if ((input[0]) <= (113.0)) {
                        if ((input[5]) <= (2.5)) {
                            memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.9761904761904762, 0.0, 0.015873015873015872, 0.0, 0.0, 0.0, 0.0, 0.007936507936507936}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.16251353919506073)) {
                            memcpy(var71, (double[]){0.00388457269700333, 0.0, 0.0, 0.5011098779134295, 0.49500554938956715, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (40.96089553833008)) {
                        if ((input[0]) <= (4512.5)) {
                            memcpy(var71, (double[]){0.0, 0.011494252873563218, 0.9885057471264368, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.0, 0.258974358974359, 0.7410256410256411, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (51.84704399108887)) {
                            memcpy(var71, (double[]){0.0, 0.900578034682081, 0.09942196531791908, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.14488636363636365, 0.15625, 0.07670454545454546, 0.0, 0.0, 0.0, 0.0, 0.6221590909090909}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[1]) <= (287790.0)) {
            if ((input[7]) <= (0.06550249829888344)) {
                if ((input[5]) <= (1378.0)) {
                    if ((input[6]) <= (0.9971387684345245)) {
                        if ((input[12]) <= (0.28289199620485306)) {
                            memcpy(var71, (double[]){0.19607843137254902, 0.0, 0.0196078431372549, 0.0, 0.0, 0.0, 0.0, 0.7843137254901961}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (6.5)) {
                            memcpy(var71, (double[]){0.9736842105263158, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.02631578947368421}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.6, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.4}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[3]) <= (13.519520282745361)) {
                    if ((input[7]) <= (0.91627636551857)) {
                        memcpy(var71, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (716.8778991699219)) {
                        if ((input[5]) <= (2141.0)) {
                            memcpy(var71, (double[]){0.9233983286908078, 0.0, 0.0, 0.0, 0.001392757660167131, 0.0, 0.0, 0.07520891364902507}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.14285714285714285, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8571428571428571, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[5]) <= (90.5)) {
                if ((input[10]) <= (0.05718035250902176)) {
                    if ((input[7]) <= (0.00037214589247014374)) {
                        if ((input[2]) <= (60.64970016479492)) {
                            memcpy(var71, (double[]){0.0, 0.5, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var71, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[3]) <= (717.9013061523438)) {
                    if ((input[10]) <= (0.12649573385715485)) {
                        if ((input[1]) <= (1869575.5)) {
                            memcpy(var71, (double[]){0.933920704845815, 0.0, 0.0, 0.0, 0.0, 0.0, 0.06607929515418502, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var71, (double[]){0.9971671388101983, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0028328611898017, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var71, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var30, var71, 8, var29);
    double var72[8];
    if ((input[2]) <= (110.31181335449219)) {
        if ((input[6]) <= (0.8887483179569244)) {
            if ((input[1]) <= (3869.5)) {
                memcpy(var72, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[4]) <= (32.0)) {
                    if ((input[10]) <= (0.36269429326057434)) {
                        if ((input[9]) <= (0.35777643078472465)) {
                            memcpy(var72, (double[]){0.01232394366197183, 0.0, 0.0, 0.4242957746478873, 0.5633802816901409, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[4]) <= (16462.0)) {
                        if ((input[4]) <= (6629.5)) {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.6865079365079365, 0.3134920634920635, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.01015228426395939, 0.9898477157360406, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var72, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[1]) <= (76821.0)) {
                if ((input[13]) <= (1.3261997699737549)) {
                    if ((input[0]) <= (224.5)) {
                        if ((input[5]) <= (1282.0)) {
                            memcpy(var72, (double[]){0.5161290322580645, 0.0, 0.4032258064516129, 0.0, 0.0, 0.0, 0.0, 0.08064516129032258}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[13]) <= (0.5853960514068604)) {
                            memcpy(var72, (double[]){0.0022727272727272726, 0.004545454545454545, 0.6454545454545455, 0.0, 0.0, 0.0, 0.07727272727272727, 0.27045454545454545}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.9532710280373832, 0.0, 0.0, 0.0, 0.0, 0.0, 0.04672897196261682}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[4]) <= (48.0)) {
                        if ((input[5]) <= (1252.0)) {
                            memcpy(var72, (double[]){0.6666666666666666, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.3333333333333333}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var72, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[0]) <= (43429.0)) {
                    if ((input[7]) <= (0.029659864492714405)) {
                        if ((input[3]) <= (0.6390270888805389)) {
                            memcpy(var72, (double[]){0.0, 0.12121212121212122, 0.8545454545454545, 0.0, 0.0, 0.0, 0.0, 0.024242424242424242}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.05269461077844311, 0.7293413173652694, 0.11736526946107785, 0.0, 0.0, 0.0, 0.09820359281437126, 0.0023952095808383233}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[2]) <= (40.291847229003906)) {
                        if ((input[5]) <= (1.5)) {
                            memcpy(var72, (double[]){0.0, 0.2261904761904762, 0.7738095238095238, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.09782608695652174, 0.9021739130434783, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (6099.5)) {
                            memcpy(var72, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.9933333333333333, 0.006666666666666667, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    } else {
        if ((input[1]) <= (1274893.5)) {
            if ((input[10]) <= (0.11026463657617569)) {
                if ((input[5]) <= (3.5)) {
                    if ((input[4]) <= (43.0)) {
                        if ((input[6]) <= (0.7741046845912933)) {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.6666666666666666, 0.3333333333333333, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[12]) <= (0.01403061207383871)) {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.9787234042553191, 0.02127659574468085, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[4]) <= (62.5)) {
                        if ((input[0]) <= (903.0)) {
                            memcpy(var72, (double[]){0.966996699669967, 0.0033003300330033004, 0.0033003300330033004, 0.0, 0.005500550055005501, 0.0022002200220022, 0.0187018701870187, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.766497461928934, 0.0, 0.0, 0.0, 0.20812182741116753, 0.0, 0.025380710659898477, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[8]) <= (0.1343393799616024)) {
                            memcpy(var72, (double[]){0.17647058823529413, 0.0, 0.0, 0.8235294117647058, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[5]) <= (5402.5)) {
                if ((input[3]) <= (718.7391662597656)) {
                    if ((input[7]) <= (0.0004042594664497301)) {
                        if ((input[4]) <= (2.5)) {
                            memcpy(var72, (double[]){0.8, 0.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.9974811083123426, 0.0025188916876574307, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var72, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[7]) <= (0.004658192861825228)) {
                    if ((input[1]) <= (3223766.5)) {
                        memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[12]) <= (0.0004177109512966126)) {
                            memcpy(var72, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var72, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var72, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var29, var72, 8, var28);
    double var73[8];
    if ((input[5]) <= (15.5)) {
        if ((input[0]) <= (126.0)) {
            if ((input[13]) <= (0.19090909510850906)) {
                if ((input[3]) <= (437.0038604736328)) {
                    if ((input[1]) <= (7475.0)) {
                        memcpy(var73, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[2]) <= (132.68939208984375)) {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[4]) <= (1.5)) {
                        memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        if ((input[6]) <= (0.027274982072412968)) {
                            memcpy(var73, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.9333333333333333, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.06666666666666667}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[5]) <= (2.5)) {
                    memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                } else {
                    if ((input[4]) <= (3.5)) {
                        memcpy(var73, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[3]) <= (391.4575500488281)) {
                            memcpy(var73, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[6]) <= (0.9374046623706818)) {
                if ((input[7]) <= (0.7308704853057861)) {
                    if ((input[12]) <= (0.34989273734390736)) {
                        if ((input[3]) <= (410.05908203125)) {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0022002200220022, 0.9284928492849285, 0.0, 0.0, 0.06930693069306931}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.2631578947368421, 0.0, 0.0, 0.7368421052631579}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[2]) <= (273.2960968017578)) {
                        if ((input[10]) <= (0.36298078298568726)) {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (5.5)) {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.18181818181818182, 0.0, 0.0, 0.0, 0.045454545454545456, 0.0, 0.0, 0.7727272727272727}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[5]) <= (0.5)) {
                    if ((input[13]) <= (0.624839186668396)) {
                        if ((input[10]) <= (0.49448123574256897)) {
                            memcpy(var73, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var73, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (1.1793479323387146)) {
                        if ((input[2]) <= (40.19052696228027)) {
                            memcpy(var73, (double[]){0.0, 0.07886435331230283, 0.9211356466876972, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.0, 0.4, 0.0, 0.0, 0.0, 0.0, 0.0, 0.6}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (409.7264404296875)) {
                            memcpy(var73, (double[]){0.0, 0.7103918228279387, 0.2512776831345826, 0.0, 0.0, 0.0, 0.0, 0.03833049403747871}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.30158730158730157, 0.031746031746031744, 0.0, 0.0, 0.0, 0.0, 0.0, 0.6666666666666666}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    } else {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[2]) <= (69.51709365844727)) {
                if ((input[6]) <= (0.9203622043132782)) {
                    if ((input[7]) <= (0.05365645733400015)) {
                        if ((input[6]) <= (0.12469381699338555)) {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var73, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[1]) <= (392865.0)) {
                        if ((input[1]) <= (118733.0)) {
                            memcpy(var73, (double[]){0.0017543859649122807, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9982456140350877, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.12121212121212122, 0.0, 0.020202020202020204, 0.0, 0.0, 0.0, 0.8585858585858586, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var73, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[6]) <= (0.8871956765651703)) {
                    if ((input[4]) <= (270.0)) {
                        if ((input[7]) <= (0.2981535345315933)) {
                            memcpy(var73, (double[]){0.9814814814814815, 0.0, 0.0, 0.0, 0.0, 0.0, 0.018518518518518517, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (1473860.5)) {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (3660.5)) {
                        if ((input[3]) <= (242.53841400146484)) {
                            memcpy(var73, (double[]){0.48717948717948717, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5128205128205128, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.9962216624685138, 0.0, 0.0, 0.0, 0.0, 0.0, 0.003778337531486146, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (614.1462097167969)) {
                            memcpy(var73, (double[]){0.0196078431372549, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9803921568627451, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var73, (double[]){0.7391304347826086, 0.0, 0.0, 0.0, 0.0, 0.0, 0.2608695652173913, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var73, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    }
    add_vectors(var28, var73, 8, var27);
    double var74[8];
    if ((input[3]) <= (127.17290878295898)) {
        if ((input[1]) <= (3956.0)) {
            memcpy(var74, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
        } else {
            if ((input[7]) <= (0.8836686611175537)) {
                if ((input[12]) <= (0.4153452552855015)) {
                    if ((input[8]) <= (0.5875985771417618)) {
                        if ((input[13]) <= (0.03632512874901295)) {
                            memcpy(var74, (double[]){0.009725906277630416, 0.022988505747126436, 0.7144120247568524, 0.0, 0.0, 0.0, 0.16976127320954906, 0.08311229000884174}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.006423982869379015, 0.6445396145610278, 0.0007137758743754461, 0.0007137758743754461, 0.0, 0.0, 0.337615988579586, 0.009992862241256246}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (30209.0)) {
                            memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 0.7914893617021277, 0.0, 0.0, 0.20851063829787234}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[1]) <= (73036.0)) {
                    if ((input[6]) <= (0.030823363922536373)) {
                        if ((input[10]) <= (0.4641089141368866)) {
                            memcpy(var74, (double[]){0.08, 0.0, 0.0, 0.92, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (69.20949172973633)) {
                            memcpy(var74, (double[]){0.08823529411764706, 0.0, 0.0, 0.4117647058823529, 0.0, 0.0, 0.0, 0.5}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.7666666666666667, 0.0, 0.0, 0.2, 0.0, 0.0, 0.0, 0.03333333333333333}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[1]) <= (74774.5)) {
                        if ((input[10]) <= (0.49369746446609497)) {
                            memcpy(var74, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var74, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    } else {
        if ((input[10]) <= (0.0609900988638401)) {
            if ((input[8]) <= (0.16184448450803757)) {
                if ((input[13]) <= (0.8076786994934082)) {
                    if ((input[3]) <= (226.88959503173828)) {
                        if ((input[9]) <= (0.333821308799088)) {
                            memcpy(var74, (double[]){0.8173913043478261, 0.0, 0.020289855072463767, 0.07246376811594203, 0.0, 0.0, 0.08985507246376812, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (137.5)) {
                            memcpy(var74, (double[]){0.982051282051282, 0.000641025641025641, 0.0019230769230769232, 0.001282051282051282, 0.0, 0.000641025641025641, 0.013461538461538462, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[1]) <= (163109.0)) {
                        if ((input[6]) <= (0.5434599965810776)) {
                            memcpy(var74, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.0, 0.01639344262295082, 0.0, 0.0, 0.0, 0.0, 0.9836065573770492, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[13]) <= (0.9525773227214813)) {
                            memcpy(var74, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var74, (double[]){0.987012987012987, 0.012987012987012988, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[6]) <= (0.20187541842460632)) {
                    memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[7]) <= (0.2331034168601036)) {
                        memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var74, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            memcpy(var74, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    }
    add_vectors(var27, var74, 8, var26);
    double var75[8];
    if ((input[8]) <= (0.2641761302947998)) {
        if ((input[2]) <= (111.1686897277832)) {
            if ((input[4]) <= (0.5)) {
                memcpy(var75, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[10]) <= (0.36269429326057434)) {
                    if ((input[5]) <= (1562.5)) {
                        if ((input[9]) <= (0.4324324205517769)) {
                            memcpy(var75, (double[]){0.06694560669456066, 0.32670850767085075, 0.3009065550906555, 0.3054393305439331, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[1]) <= (1266642.5)) {
                if ((input[10]) <= (0.12245728075504303)) {
                    if ((input[3]) <= (21.888046264648438)) {
                        memcpy(var75, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[5]) <= (2504.0)) {
                            memcpy(var75, (double[]){0.9710144927536232, 0.000966183574879227, 0.007729468599033816, 0.012560386473429951, 0.0, 0.007729468599033816, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var75, (double[]){0.22448979591836735, 0.0, 0.0, 0.0, 0.0, 0.0, 0.7755102040816326, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (1300.2678833007812)) {
                    if ((input[5]) <= (5402.5)) {
                        if ((input[5]) <= (3.5)) {
                            memcpy(var75, (double[]){0.7857142857142857, 0.21428571428571427, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var75, (double[]){0.9913473423980222, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.00865265760197775}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (5557.0)) {
                            memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var75, (double[]){0.98989898989899, 0.0, 0.0, 0.0, 0.0, 0.0, 0.010101010101010102, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        if ((input[10]) <= (0.1587301641702652)) {
            if ((input[6]) <= (0.20187541842460632)) {
                memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[8]) <= (0.43390804529190063)) {
                    if ((input[2]) <= (411.4060974121094)) {
                        memcpy(var75, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            memcpy(var75, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    }
    add_vectors(var26, var75, 8, var25);
    double var76[8];
    if ((input[13]) <= (0.8354564607143402)) {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[3]) <= (110.0412712097168)) {
                if ((input[7]) <= (0.8939029276371002)) {
                    if ((input[6]) <= (0.9188886284828186)) {
                        if ((input[0]) <= (123.5)) {
                            memcpy(var76, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.001053740779768177, 0.6396206533192834, 0.35721812434141204, 0.002107481559536354, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (224.5)) {
                            memcpy(var76, (double[]){0.07692307692307693, 0.0, 0.12307692307692308, 0.0, 0.0, 0.0, 0.8, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.0, 0.04767184035476718, 0.9423503325942351, 0.0, 0.0, 0.0, 0.009977827050997782, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[13]) <= (0.003816793905571103)) {
                        if ((input[9]) <= (0.000014371946235769428)) {
                            memcpy(var76, (double[]){0.09447674418604651, 0.0, 0.0, 0.9055232558139535, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.02702702702702703, 0.0, 0.0, 0.972972972972973, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var76, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[5]) <= (8.5)) {
                    if ((input[1]) <= (32059.5)) {
                        if ((input[6]) <= (0.0526003111153841)) {
                            memcpy(var76, (double[]){0.9666666666666667, 0.0, 0.0, 0.03333333333333333, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.1896551724137931, 0.0, 0.22413793103448276, 0.22413793103448276, 0.1206896551724138, 0.2413793103448276, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (4.5)) {
                            memcpy(var76, (double[]){0.2517985611510791, 0.014388489208633094, 0.050359712230215826, 0.04316546762589928, 0.6330935251798561, 0.007194244604316547, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.0, 0.0, 0.037037037037037035, 0.037037037037037035, 0.9259259259259259, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[8]) <= (0.4622628837823868)) {
                        if ((input[4]) <= (146.0)) {
                            memcpy(var76, (double[]){0.9482669425763063, 0.0010346611484738748, 0.002586652871184687, 0.0, 0.0005173305742369374, 0.007242628039317123, 0.04035178479048112, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.0, 0.0, 0.16666666666666666, 0.5, 0.3333333333333333, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[5]) <= (1378.0)) {
            if ((input[7]) <= (0.03160265181213617)) {
                if ((input[10]) <= (0.4889380633831024)) {
                    if ((input[1]) <= (26852.5)) {
                        if ((input[8]) <= (0.48346054553985596)) {
                            memcpy(var76, (double[]){0.46153846153846156, 0.07692307692307693, 0.0, 0.0, 0.0, 0.46153846153846156, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (34.83283042907715)) {
                            memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.0, 0.918918918918919, 0.08108108108108109, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[3]) <= (10.690512657165527)) {
                    if ((input[6]) <= (0.005812689196318388)) {
                        memcpy(var76, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[6]) <= (0.006420694524422288)) {
                            memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.1111111111111111, 0.0, 0.0, 0.6666666666666666, 0.0, 0.0, 0.0, 0.2222222222222222}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[4]) <= (4.5)) {
                        if ((input[10]) <= (0.2383333295583725)) {
                            memcpy(var76, (double[]){0.8125, 0.0, 0.0, 0.0, 0.125, 0.0625, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[12]) <= (0.0016106494003906846)) {
                            memcpy(var76, (double[]){0.9333333333333333, 0.0, 0.0, 0.0, 0.044444444444444446, 0.0, 0.0, 0.022222222222222223}, 8 * sizeof(double));
                        } else {
                            memcpy(var76, (double[]){0.42857142857142855, 0.0, 0.0, 0.42857142857142855, 0.14285714285714285, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[1]) <= (4206771.0)) {
                memcpy(var76, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
            } else {
                memcpy(var76, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var25, var76, 8, var24);
    double var77[8];
    if ((input[0]) <= (126.0)) {
        if ((input[10]) <= (0.39320388436317444)) {
            if ((input[1]) <= (22902.0)) {
                memcpy(var77, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[3]) <= (371.3787078857422)) {
                    if ((input[2]) <= (222.5431900024414)) {
                        memcpy(var77, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var77, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var77, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[8]) <= (0.09340992197394371)) {
            if ((input[1]) <= (4194959.5)) {
                if ((input[7]) <= (0.1072242371737957)) {
                    if ((input[6]) <= (0.6889758557081223)) {
                        memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[5]) <= (2450.5)) {
                            memcpy(var77, (double[]){0.10931518502764781, 0.3964270523181625, 0.3675031901318588, 0.0, 0.0, 0.0, 0.0, 0.1267545725223309}, 8 * sizeof(double));
                        } else {
                            memcpy(var77, (double[]){0.0037641154328732747, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9962358845671268, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[10]) <= (0.05718035250902176)) {
                        if ((input[4]) <= (59.0)) {
                            memcpy(var77, (double[]){0.7032520325203252, 0.0, 0.0, 0.2953929539295393, 0.0, 0.0, 0.0013550135501355014, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var77, (double[]){0.0028530670470756064, 0.0, 0.0, 0.9971469329529244, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[2]) <= (258.01187324523926)) {
                    memcpy(var77, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[4]) <= (2.5)) {
                        if ((input[2]) <= (911.6588134765625)) {
                            memcpy(var77, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var77, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var77, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[4]) <= (48.0)) {
                if ((input[3]) <= (414.24034118652344)) {
                    if ((input[0]) <= (685.5)) {
                        if ((input[0]) <= (271.5)) {
                            memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 0.2441860465116279, 0.0, 0.0, 0.7558139534883721}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[10]) <= (0.11747343838214874)) {
                        memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var77, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var24, var77, 8, var23);
    double var78[8];
    if ((input[3]) <= (115.33787155151367)) {
        if ((input[6]) <= (0.921909511089325)) {
            if ((input[7]) <= (0.9464423358440399)) {
                if ((input[2]) <= (14.0)) {
                    memcpy(var78, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[12]) <= (0.6256097555160522)) {
                        if ((input[8]) <= (0.6330106407403946)) {
                            memcpy(var78, (double[]){0.8968253968253969, 0.0, 0.0, 0.05555555555555555, 0.0, 0.0, 0.0, 0.047619047619047616}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.0, 0.0, 0.0, 0.0, 0.9437229437229437, 0.0, 0.0, 0.05627705627705628}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var78, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[1]) <= (74601.0)) {
                    if ((input[12]) <= (0.0006410256610251963)) {
                        if ((input[4]) <= (43.5)) {
                            memcpy(var78, (double[]){0.35714285714285715, 0.0, 0.0, 0.01904761904761905, 0.0, 0.0, 0.0, 0.6238095238095238}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (75.96475219726562)) {
                            memcpy(var78, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.18181818181818182, 0.0, 0.0, 0.8181818181818182, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var78, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[4]) <= (14.5)) {
                if ((input[0]) <= (228.5)) {
                    if ((input[6]) <= (0.9977169036865234)) {
                        if ((input[4]) <= (5.5)) {
                            memcpy(var78, (double[]){0.012987012987012988, 0.0, 0.0, 0.0, 0.0, 0.0, 0.987012987012987, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.25, 0.0, 0.0, 0.0, 0.0, 0.0, 0.75, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (1254.5)) {
                            memcpy(var78, (double[]){0.36585365853658536, 0.0, 0.6341463414634146, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[7]) <= (0.014316703658550978)) {
                        if ((input[5]) <= (1429.0)) {
                            memcpy(var78, (double[]){0.0, 0.44873501997336884, 0.4367509986684421, 0.0, 0.0, 0.0, 0.0, 0.11451398135818908}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[9]) <= (0.0038314175326377153)) {
                            memcpy(var78, (double[]){0.0, 0.2413793103448276, 0.13793103448275862, 0.0, 0.0, 0.0, 0.0, 0.6206896551724138}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[13]) <= (0.5168996378779411)) {
                    memcpy(var78, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var78, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[8]) <= (0.12320279330015182)) {
                if ((input[5]) <= (2652.5)) {
                    if ((input[4]) <= (37.5)) {
                        if ((input[12]) <= (0.4581395238637924)) {
                            memcpy(var78, (double[]){0.9813084112149533, 0.007696536558548653, 0.006047278724573941, 0.0021990104452996153, 0.0, 0.0, 0.002748763056624519, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.05263157894736842, 0.0, 0.0, 0.0, 0.0, 0.9473684210526315, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[13]) <= (0.7922933548688889)) {
                            memcpy(var78, (double[]){0.07142857142857142, 0.0, 0.25, 0.6785714285714286, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[0]) <= (2557.0)) {
                        if ((input[4]) <= (19.0)) {
                            memcpy(var78, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.9999755620956421)) {
                            memcpy(var78, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.9375, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0625, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[12]) <= (0.0873949583619833)) {
                    if ((input[2]) <= (248.28252410888672)) {
                        memcpy(var78, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[3]) <= (457.14183044433594)) {
                            memcpy(var78, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var78, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var78, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            memcpy(var78, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    }
    add_vectors(var23, var78, 8, var22);
    double var79[8];
    if ((input[0]) <= (126.0)) {
        if ((input[10]) <= (0.3857142925262451)) {
            if ((input[13]) <= (0.09232954680919647)) {
                memcpy(var79, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[0]) <= (110.5)) {
                    memcpy(var79, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[3]) <= (254.42111206054688)) {
                        memcpy(var79, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[1]) <= (24507.5)) {
                            memcpy(var79, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var79, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[8]) <= (0.09340992197394371)) {
            if ((input[6]) <= (0.8887483179569244)) {
                if ((input[3]) <= (100.89868545532227)) {
                    if ((input[12]) <= (0.3998430259525776)) {
                        if ((input[1]) <= (74601.0)) {
                            memcpy(var79, (double[]){0.045951859956236324, 0.0, 0.0, 0.6717724288840262, 0.0, 0.0, 0.0, 0.28227571115973743}, 8 * sizeof(double));
                        } else {
                            memcpy(var79, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[5]) <= (24.5)) {
                        if ((input[3]) <= (382.87158203125)) {
                            memcpy(var79, (double[]){0.14864864864864866, 0.0, 0.0, 0.527027027027027, 0.0, 0.2972972972972973, 0.0, 0.02702702702702703}, 8 * sizeof(double));
                        } else {
                            memcpy(var79, (double[]){0.06870229007633588, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9312977099236641}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.14421338587999344)) {
                            memcpy(var79, (double[]){0.9577735124760077, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.04222648752399232}, 8 * sizeof(double));
                        } else {
                            memcpy(var79, (double[]){0.7021276595744681, 0.0, 0.0, 0.0, 0.0, 0.02127659574468085, 0.0070921985815602835, 0.2695035460992908}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[10]) <= (0.04062318056821823)) {
                    if ((input[5]) <= (15.5)) {
                        if ((input[2]) <= (41.09253692626953)) {
                            memcpy(var79, (double[]){0.0, 0.10449438202247191, 0.895505617977528, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var79, (double[]){0.03905447070914697, 0.8581706063720452, 0.10277492291880781, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (214.4110870361328)) {
                            memcpy(var79, (double[]){0.0057306590257879654, 0.0028653295128939827, 0.004297994269340974, 0.0, 0.0, 0.0, 0.9871060171919771, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var79, (double[]){0.9455864570737605, 0.0, 0.0, 0.0, 0.0, 0.0, 0.05441354292623942, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[0]) <= (692.5)) {
                if ((input[4]) <= (50.0)) {
                    if ((input[1]) <= (14530.0)) {
                        if ((input[13]) <= (0.5578947365283966)) {
                            memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.2960498481988907)) {
                            memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 0.04017857142857143, 0.0, 0.0, 0.9598214285714286}, 8 * sizeof(double));
                        } else {
                            memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 0.6, 0.0, 0.0, 0.4}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (571.1725463867188)) {
                    memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var79, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var22, var79, 8, var21);
    double var80[8];
    if ((input[5]) <= (15.5)) {
        if ((input[8]) <= (0.09248630329966545)) {
            if ((input[0]) <= (130.5)) {
                if ((input[13]) <= (0.08533653989434242)) {
                    if ((input[10]) <= (0.5)) {
                        memcpy(var80, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[10]) <= (0.39320388436317444)) {
                        if ((input[9]) <= (0.01904761977493763)) {
                            memcpy(var80, (double[]){0.8928571428571429, 0.0, 0.07142857142857142, 0.03571428571428571, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[13]) <= (0.900029182434082)) {
                    if ((input[12]) <= (0.37220626324415207)) {
                        if ((input[2]) <= (50.61723327636719)) {
                            memcpy(var80, (double[]){0.0, 0.026676829268292682, 0.6592987804878049, 0.31402439024390244, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.047619047619047616, 0.004645760743321719, 0.0313588850174216, 0.4518002322880372, 0.0, 0.0, 0.0, 0.4645760743321719}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[9]) <= (0.48181508388370275)) {
                        if ((input[1]) <= (26175.5)) {
                            memcpy(var80, (double[]){0.0, 0.06060606060606061, 0.0, 0.3939393939393939, 0.0, 0.0, 0.0, 0.5454545454545454}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.0, 0.9266247379454927, 0.0, 0.03773584905660377, 0.0, 0.0, 0.0, 0.03563941299790356}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[2]) <= (560.5619201660156)) {
                if ((input[10]) <= (0.43934911489486694)) {
                    if ((input[8]) <= (0.30613337457180023)) {
                        if ((input[0]) <= (326.0)) {
                            memcpy(var80, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[3]) <= (78.54237365722656)) {
            if ((input[1]) <= (7910.0)) {
                memcpy(var80, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[0]) <= (189.5)) {
                    if ((input[7]) <= (0.48165322560817003)) {
                        memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var80, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[6]) <= (0.4874201975762844)) {
                        if ((input[1]) <= (27912.0)) {
                            memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.4, 0.0, 0.0, 0.0, 0.13333333333333333, 0.0, 0.0, 0.4666666666666667}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.9937333762645721)) {
                            memcpy(var80, (double[]){0.0, 0.0, 0.03225806451612903, 0.0, 0.0, 0.0, 0.8387096774193549, 0.12903225806451613}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.0, 0.004942339373970346, 0.0, 0.0, 0.0, 0.0, 0.9950576606260296, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[2]) <= (101.5223388671875)) {
                if ((input[0]) <= (311.0)) {
                    if ((input[12]) <= (0.04963935352861881)) {
                        if ((input[1]) <= (10348.5)) {
                            memcpy(var80, (double[]){0.7142857142857143, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.2857142857142857}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9733333333333334, 0.02666666666666667}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[0]) <= (594.5)) {
                        if ((input[10]) <= (0.3859890103340149)) {
                            memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[13]) <= (0.041054047644138336)) {
                            memcpy(var80, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.125, 0.125, 0.25, 0.5, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[10]) <= (0.04062318056821823)) {
                    if ((input[5]) <= (3422.5)) {
                        if ((input[5]) <= (2652.5)) {
                            memcpy(var80, (double[]){0.9979395604395604, 0.0, 0.0, 0.0, 0.0013736263736263737, 0.0006868131868131869, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.9629629629629629, 0.0, 0.0, 0.0, 0.0, 0.0, 0.037037037037037035, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (235.8050765991211)) {
                            memcpy(var80, (double[]){0.037037037037037035, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9629629629629629, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var80, (double[]){0.9344262295081968, 0.0, 0.0, 0.0, 0.0, 0.0, 0.06557377049180328, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var80, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var21, var80, 8, var20);
    double var81[8];
    if ((input[13]) <= (0.8354564607143402)) {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[5]) <= (8.5)) {
                if ((input[8]) <= (0.10730268829502165)) {
                    if ((input[0]) <= (107.0)) {
                        memcpy(var81, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[9]) <= (0.4541424158960581)) {
                            memcpy(var81, (double[]){0.007441327990841442, 0.019461934745277618, 0.499141385231826, 0.47395535203205497, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (72.85386657714844)) {
                    if ((input[1]) <= (23631.0)) {
                        if ((input[7]) <= (0.07963777892291546)) {
                            memcpy(var81, (double[]){0.0196078431372549, 0.0, 0.00784313725490196, 0.0, 0.011764705882352941, 0.0, 0.9607843137254902, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.8888888888888888, 0.0, 0.0, 0.1111111111111111, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[8]) <= (0.395303338766098)) {
                            memcpy(var81, (double[]){0.1875, 0.0, 0.4375, 0.22916666666666666, 0.0, 0.14583333333333334, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (15.5)) {
                        if ((input[8]) <= (0.4576168358325958)) {
                            memcpy(var81, (double[]){0.9166666666666666, 0.011904761904761904, 0.023809523809523808, 0.03571428571428571, 0.0, 0.011904761904761904, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[8]) <= (0.4622628837823868)) {
                            memcpy(var81, (double[]){0.9812606473594548, 0.0, 0.0, 0.001135718341851221, 0.0, 0.001135718341851221, 0.016467915956842702, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[1]) <= (73045.0)) {
            if ((input[12]) <= (0.6033390834927559)) {
                if ((input[7]) <= (0.44347404688596725)) {
                    if ((input[8]) <= (0.45806507545057684)) {
                        if ((input[4]) <= (46.0)) {
                            memcpy(var81, (double[]){0.014184397163120567, 0.1347517730496454, 0.0, 0.0, 0.0, 0.0, 0.8486997635933806, 0.002364066193853428}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (42.76272201538086)) {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.18181818181818182, 0.0, 0.0, 0.8181818181818182}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[6]) <= (0.009049959015101194)) {
                        if ((input[3]) <= (0.24892191588878632)) {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.9090909090909091, 0.0, 0.0, 0.0, 0.09090909090909091}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (19.702524185180664)) {
                            memcpy(var81, (double[]){0.14285714285714285, 0.0, 0.0, 0.7142857142857143, 0.0, 0.0, 0.0, 0.14285714285714285}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.96, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.04}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[5]) <= (26.0)) {
                if ((input[6]) <= (0.4989671241492033)) {
                    if ((input[10]) <= (0.325531929731369)) {
                        if ((input[12]) <= (0.00016655890431138687)) {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.4897959183673469, 0.5102040816326531, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.8333333333333334, 0.16666666666666666, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (318.07765197753906)) {
                        memcpy(var81, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[0]) <= (9803.0)) {
                    if ((input[5]) <= (2792.5)) {
                        if ((input[10]) <= (0.2799227833747864)) {
                            memcpy(var81, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var81, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var81, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var20, var81, 8, var19);
    double var82[8];
    if ((input[2]) <= (110.31181335449219)) {
        if ((input[5]) <= (1562.5)) {
            if ((input[6]) <= (0.921909511089325)) {
                if ((input[7]) <= (0.8782665431499481)) {
                    if ((input[8]) <= (0.3639143705368042)) {
                        if ((input[6]) <= (0.0006031363154761493)) {
                            memcpy(var82, (double[]){0.8039473684210526, 0.0, 0.0, 0.0, 0.0, 0.19605263157894737, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.27906976744186046, 0.0, 0.006644518272425249, 0.029900332225913623, 0.0, 0.6644518272425249, 0.0, 0.019933554817275746}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (304.45484924316406)) {
                            memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.9234184239733629, 0.0, 0.0, 0.07658157602663707}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[7]) <= (0.9999859631061554)) {
                        if ((input[6]) <= (0.0013838655431754887)) {
                            memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.9958677685950413, 0.0, 0.0, 0.0, 0.004132231404958678}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.010416666666666666, 0.0, 0.0, 0.8151041666666666, 0.0, 0.0, 0.0, 0.17447916666666666}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (46.31505012512207)) {
                            memcpy(var82, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.11956521739130435, 0.0, 0.0, 0.5434782608695652, 0.0, 0.0, 0.0, 0.33695652173913043}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[3]) <= (1.1771713495254517)) {
                    if ((input[5]) <= (0.5)) {
                        if ((input[13]) <= (0.49996519088745117)) {
                            memcpy(var82, (double[]){0.1346153846153846, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8653846153846154}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (4484.5)) {
                            memcpy(var82, (double[]){0.010309278350515464, 0.002577319587628866, 0.9510309278350515, 0.0, 0.0, 0.0, 0.0, 0.03608247422680412}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.0, 0.2007168458781362, 0.7992831541218638, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[0]) <= (817.5)) {
                        if ((input[1]) <= (3734.5)) {
                            memcpy(var82, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.019417475728155338, 0.04854368932038835, 0.6893203883495146, 0.0, 0.0, 0.0, 0.0, 0.24271844660194175}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[13]) <= (0.04438241757452488)) {
                            memcpy(var82, (double[]){0.22321428571428573, 0.017857142857142856, 0.7232142857142857, 0.0, 0.0, 0.0, 0.0, 0.03571428571428571}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[7]) <= (0.7548590898513794)) {
            if ((input[0]) <= (1586.0)) {
                if ((input[10]) <= (0.11163153499364853)) {
                    if ((input[1]) <= (132613.5)) {
                        if ((input[13]) <= (0.668789803981781)) {
                            memcpy(var82, (double[]){0.933852140077821, 0.007782101167315175, 0.011673151750972763, 0.0, 0.03501945525291829, 0.0, 0.011673151750972763, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (555.7516784667969)) {
                            memcpy(var82, (double[]){0.17073170731707318, 0.0, 0.0, 0.0, 0.7439024390243902, 0.036585365853658534, 0.04878048780487805, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.9354838709677419, 0.0, 0.0, 0.0, 0.0, 0.0, 0.06451612903225806, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[8]) <= (0.15784405439626426)) {
                    if ((input[10]) <= (0.06565086543560028)) {
                        if ((input[0]) <= (2426.0)) {
                            memcpy(var82, (double[]){0.8545454545454545, 0.0, 0.0, 0.0, 0.0, 0.0, 0.14545454545454545, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.9897510980966325, 0.005856515373352855, 0.0, 0.0, 0.0, 0.0, 0.004392386530014641, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[10]) <= (0.22702331840991974)) {
                        memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[5]) <= (3.5)) {
                if ((input[5]) <= (1.5)) {
                    if ((input[10]) <= (0.39320388436317444)) {
                        memcpy(var82, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var82, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[10]) <= (0.1873401552438736)) {
                    if ((input[4]) <= (256.0)) {
                        if ((input[8]) <= (0.13800188899040222)) {
                            memcpy(var82, (double[]){0.9961051606621227, 0.0, 0.0, 0.0038948393378773127, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var82, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var82, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var19, var82, 8, var18);
    double var83[8];
    if ((input[6]) <= (0.979724794626236)) {
        if ((input[0]) <= (125.5)) {
            if ((input[12]) <= (0.23492063581943512)) {
                if ((input[1]) <= (74298.0)) {
                    if ((input[6]) <= (0.13446328043937683)) {
                        if ((input[1]) <= (21973.0)) {
                            memcpy(var83, (double[]){0.9988137603795967, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0011862396204033216}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.953125, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.046875}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[6]) <= (0.44172932766377926)) {
                        memcpy(var83, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[9]) <= (0.01904761977493763)) {
                    memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var83, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[4]) <= (116.5)) {
                if ((input[12]) <= (0.3530762270092964)) {
                    if ((input[5]) <= (15.0)) {
                        if ((input[8]) <= (0.09231705055572093)) {
                            memcpy(var83, (double[]){0.0018867924528301887, 0.0037735849056603774, 0.03018867924528302, 0.4849056603773585, 0.0, 0.0, 0.0, 0.47924528301886793}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.0, 0.0, 0.0, 0.0, 0.6915254237288135, 0.0, 0.0, 0.30847457627118646}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (1696.5)) {
                            memcpy(var83, (double[]){0.5925925925925926, 0.0, 0.0, 0.0, 0.0, 0.0, 0.053497942386831275, 0.35390946502057613}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.9828767123287672, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.017123287671232876}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var83, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (64.97553634643555)) {
                    if ((input[7]) <= (0.4136032611131668)) {
                        if ((input[2]) <= (47.80191230773926)) {
                            memcpy(var83, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.0, 0.0, 0.045454545454545456, 0.0, 0.9545454545454546, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var83, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[8]) <= (0.13390009689101134)) {
                        if ((input[2]) <= (349.97377014160156)) {
                            memcpy(var83, (double[]){0.0, 0.0, 0.00819672131147541, 0.9918032786885246, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var83, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    } else {
        if ((input[3]) <= (211.76041412353516)) {
            if ((input[4]) <= (14.5)) {
                if ((input[13]) <= (1.8248618841171265)) {
                    if ((input[3]) <= (5.276511192321777)) {
                        if ((input[1]) <= (8784.0)) {
                            memcpy(var83, (double[]){0.07511737089201878, 0.0, 0.10328638497652583, 0.0, 0.0, 0.0, 0.8169014084507042, 0.004694835680751174}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.0, 0.16467780429594273, 0.6348448687350835, 0.0, 0.0, 0.0, 0.007159904534606206, 0.19331742243436753}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (846.5)) {
                            memcpy(var83, (double[]){0.058823529411764705, 0.006535947712418301, 0.27450980392156865, 0.0, 0.0, 0.0, 0.5032679738562091, 0.1568627450980392}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.002890173410404624, 0.8554913294797688, 0.10982658959537572, 0.0, 0.0, 0.0, 0.0, 0.031791907514450865}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[0]) <= (101.5)) {
                        memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[1]) <= (590129.5)) {
                            memcpy(var83, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[2]) <= (40.743778228759766)) {
                    if ((input[2]) <= (40.256656646728516)) {
                        if ((input[6]) <= (0.9999191164970398)) {
                            memcpy(var83, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.0, 0.07268170426065163, 0.9273182957393483, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (40.26312065124512)) {
                            memcpy(var83, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.0, 0.23684210526315788, 0.7631578947368421, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[13]) <= (0.531321857124567)) {
                        memcpy(var83, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var83, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[5]) <= (13.5)) {
                if ((input[0]) <= (1688.5)) {
                    if ((input[1]) <= (90875.5)) {
                        if ((input[0]) <= (79.0)) {
                            memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.0, 0.36363636363636365, 0.5454545454545454, 0.0, 0.0, 0.0, 0.0, 0.09090909090909091}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.017441383562982082)) {
                            memcpy(var83, (double[]){0.05154639175257732, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9484536082474226}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[6]) <= (0.9996463358402252)) {
                        if ((input[5]) <= (3.5)) {
                            memcpy(var83, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (659.03076171875)) {
                            memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[0]) <= (1060.0)) {
                    if ((input[10]) <= (0.21448275446891785)) {
                        if ((input[2]) <= (145.15892028808594)) {
                            memcpy(var83, (double[]){0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.625, 0.0, 0.0, 0.0, 0.0, 0.0, 0.375, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var83, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[5]) <= (5402.5)) {
                        if ((input[6]) <= (0.9833138585090637)) {
                            memcpy(var83, (double[]){0.6666666666666666, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.3333333333333333}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){0.9973118279569892, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.002688172043010753}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (679.2550048828125)) {
                            memcpy(var83, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var83, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    }
    add_vectors(var18, var83, 8, var17);
    double var84[8];
    if ((input[8]) <= (0.16184448450803757)) {
        if ((input[4]) <= (115.5)) {
            if ((input[5]) <= (2450.5)) {
                if ((input[9]) <= (0.3107711002230644)) {
                    if ((input[10]) <= (0.04062318056821823)) {
                        if ((input[2]) <= (78.5885009765625)) {
                            memcpy(var84, (double[]){0.3925399644760213, 0.23801065719360567, 0.23564239194789816, 0.13380698638247485, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var84, (double[]){0.9766913018760659, 0.003979533826037522, 0.003979533826037522, 0.015349630471859011, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var84, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var84, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (320.22442626953125)) {
                    if ((input[4]) <= (53.0)) {
                        memcpy(var84, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var84, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[2]) <= (494.38995361328125)) {
                        if ((input[13]) <= (0.28916630148887634)) {
                            memcpy(var84, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var84, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (13.5)) {
                            memcpy(var84, (double[]){0.2727272727272727, 0.0, 0.0, 0.0, 0.0, 0.0, 0.7272727272727273, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var84, (double[]){0.9966442953020134, 0.0, 0.0, 0.0, 0.0, 0.0, 0.003355704697986577, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[7]) <= (0.4122302904725075)) {
                if ((input[8]) <= (0.00003374957668711431)) {
                    if ((input[2]) <= (40.28353691101074)) {
                        if ((input[13]) <= (690.3156150290743)) {
                            memcpy(var84, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var84, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (2530.0)) {
                            memcpy(var84, (double[]){0.0, 0.06060606060606061, 0.9393939393939394, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var84, (double[]){0.0, 0.9942418426103646, 0.005758157389635317, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var84, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[5]) <= (7327.0)) {
                    memcpy(var84, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var84, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        if ((input[10]) <= (0.11747343838214874)) {
            if ((input[12]) <= (0.04625850357115269)) {
                if ((input[2]) <= (118.03689193725586)) {
                    memcpy(var84, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[3]) <= (217.47674942016602)) {
                        memcpy(var84, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[1]) <= (28368.5)) {
                            memcpy(var84, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var84, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[8]) <= (0.6299019604921341)) {
                    memcpy(var84, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var84, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            memcpy(var84, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    }
    add_vectors(var17, var84, 8, var16);
    double var85[8];
    if ((input[10]) <= (0.04062318056821823)) {
        if ((input[7]) <= (0.26800093054771423)) {
            if ((input[0]) <= (129.5)) {
                if ((input[0]) <= (104.5)) {
                    memcpy(var85, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[0]) <= (120.5)) {
                        memcpy(var85, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var85, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[5]) <= (15.5)) {
                    if ((input[0]) <= (752.5)) {
                        if ((input[2]) <= (39.55061340332031)) {
                            memcpy(var85, (double[]){0.0, 0.0, 0.0, 0.0, 0.22807017543859648, 0.7719298245614035, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var85, (double[]){0.007058823529411765, 0.03529411764705882, 0.8352941176470589, 0.0, 0.06588235294117648, 0.05647058823529412, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (39.87775802612305)) {
                            memcpy(var85, (double[]){0.0, 0.0, 0.0, 0.0, 0.8282290279627164, 0.17177097203728361, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var85, (double[]){0.01758641600970285, 0.5494238932686477, 0.3395997574287447, 0.0, 0.09217707701637357, 0.001212856276531231, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (136.44679260253906)) {
                        if ((input[5]) <= (1430.5)) {
                            memcpy(var85, (double[]){0.890625, 0.0, 0.03125, 0.0, 0.046875, 0.03125, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var85, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (2441.0)) {
                            memcpy(var85, (double[]){0.8207547169811321, 0.0, 0.0, 0.0, 0.02830188679245283, 0.0, 0.1509433962264151, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var85, (double[]){0.9936908517350158, 0.0, 0.0, 0.0, 0.0, 0.0, 0.006309148264984227, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[12]) <= (0.09212454408407211)) {
                if ((input[2]) <= (78.86909866333008)) {
                    if ((input[5]) <= (14.5)) {
                        if ((input[1]) <= (3918.5)) {
                            memcpy(var85, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var85, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (17590.0)) {
                            memcpy(var85, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var85, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (148.82177734375)) {
                        if ((input[3]) <= (21.888046264648438)) {
                            memcpy(var85, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var85, (double[]){0.8614864864864865, 0.0, 0.0, 0.13851351351351351, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (3.5)) {
                            memcpy(var85, (double[]){0.0, 0.0, 0.0, 0.6666666666666666, 0.3333333333333333, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var85, (double[]){0.9749144811858609, 0.0, 0.0, 0.0011402508551881414, 0.02394526795895097, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var85, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    } else {
        memcpy(var85, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var16, var85, 8, var15);
    double var86[8];
    if ((input[10]) <= (0.05718035250902176)) {
        if ((input[2]) <= (110.71862030029297)) {
            if ((input[8]) <= (0.311422910541296)) {
                if ((input[0]) <= (122.5)) {
                    if ((input[3]) <= (211.23993682861328)) {
                        memcpy(var86, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var86, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[5]) <= (1430.5)) {
                        if ((input[6]) <= (0.6277937144041061)) {
                            memcpy(var86, (double[]){0.0, 0.0, 0.0, 0.6880131362889984, 0.0, 0.31198686371100165, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var86, (double[]){0.024442082890541977, 0.48405951115834217, 0.4914984059511158, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var86, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var86, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[4]) <= (116.5)) {
                if ((input[6]) <= (0.024565174244344234)) {
                    if ((input[13]) <= (0.17978458851575851)) {
                        if ((input[8]) <= (0.10521500557661057)) {
                            memcpy(var86, (double[]){0.9915254237288136, 0.0, 0.0, 0.00847457627118644, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var86, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var86, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[5]) <= (5185.0)) {
                        if ((input[2]) <= (126.58589172363281)) {
                            memcpy(var86, (double[]){0.8636363636363636, 0.0, 0.0, 0.0, 0.045454545454545456, 0.0, 0.09090909090909091, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var86, (double[]){0.9860432658757851, 0.0027913468248429866, 0.0013956734124214933, 0.0006978367062107466, 0.00418702023726448, 0.0034891835310537334, 0.0013956734124214933, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (679.2550048828125)) {
                            memcpy(var86, (double[]){0.22727272727272727, 0.0, 0.0, 0.0, 0.0, 0.0, 0.7727272727272727, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var86, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[3]) <= (221.52959060668945)) {
                    memcpy(var86, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[0]) <= (11786.5)) {
                        if ((input[8]) <= (0.13384956121444702)) {
                            memcpy(var86, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var86, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var86, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    } else {
        memcpy(var86, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var15, var86, 8, var14);
    double var87[8];
    if ((input[5]) <= (15.5)) {
        if ((input[0]) <= (107.5)) {
            if ((input[13]) <= (0.21111111342906952)) {
                memcpy(var87, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                if ((input[5]) <= (2.5)) {
                    memcpy(var87, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                } else {
                    memcpy(var87, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[10]) <= (0.2383333295583725)) {
                if ((input[9]) <= (0.33237103279680014)) {
                    if ((input[4]) <= (21761.5)) {
                        if ((input[0]) <= (759.5)) {
                            memcpy(var87, (double[]){0.0136986301369863, 0.0273972602739726, 0.5496575342465754, 0.22945205479452055, 0.1797945205479452, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var87, (double[]){0.00972972972972973, 0.31027027027027027, 0.11711711711711711, 0.2774774774774775, 0.28540540540540543, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (73514.5)) {
                            memcpy(var87, (double[]){0.0, 0.14937759336099585, 0.8506224066390041, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var87, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var87, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var87, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[2]) <= (68.31125259399414)) {
            if ((input[10]) <= (0.43934911489486694)) {
                if ((input[0]) <= (127.0)) {
                    memcpy(var87, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[12]) <= (0.40887884981930256)) {
                        if ((input[3]) <= (179.9879608154297)) {
                            memcpy(var87, (double[]){0.0, 0.0, 0.0030534351145038168, 0.0, 0.0, 0.0, 0.9969465648854962, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var87, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var87, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var87, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[3]) <= (717.9013061523438)) {
                if ((input[8]) <= (0.4523744285106659)) {
                    if ((input[0]) <= (2235.0)) {
                        if ((input[7]) <= (0.06994787603616714)) {
                            memcpy(var87, (double[]){0.3869346733668342, 0.0, 0.0, 0.0, 0.0, 0.0, 0.39195979899497485, 0.22110552763819097}, 8 * sizeof(double));
                        } else {
                            memcpy(var87, (double[]){0.9330900243309003, 0.0, 0.0, 0.0, 0.0, 0.0, 0.009732360097323601, 0.057177615571776155}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (165.58648681640625)) {
                            memcpy(var87, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var87, (double[]){0.9989473684210526, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0010526315789473684, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[10]) <= (0.2271309792995453)) {
                        memcpy(var87, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var87, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                memcpy(var87, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var14, var87, 8, var13);
    double var88[8];
    if ((input[0]) <= (129.0)) {
        if ((input[13]) <= (12605.7646484375)) {
            if ((input[4]) <= (32.0)) {
                if ((input[10]) <= (0.3857142925262451)) {
                    memcpy(var88, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var88, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var88, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[8]) <= (0.49130433797836304)) {
                memcpy(var88, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            } else {
                memcpy(var88, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[2]) <= (149.02095794677734)) {
            if ((input[4]) <= (16.0)) {
                if ((input[5]) <= (1430.5)) {
                    if ((input[5]) <= (14.5)) {
                        if ((input[0]) <= (1722.5)) {
                            memcpy(var88, (double[]){0.0, 0.10459433040078202, 0.17204301075268819, 0.011730205278592375, 0.10752688172043011, 0.375366568914956, 0.0, 0.2287390029325513}, 8 * sizeof(double));
                        } else {
                            memcpy(var88, (double[]){0.0, 0.2817982456140351, 0.25548245614035087, 0.19846491228070176, 0.2631578947368421, 0.0010964912280701754, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.35185185074806213)) {
                            memcpy(var88, (double[]){0.9509803921568627, 0.0, 0.0392156862745098, 0.0, 0.0, 0.00980392156862745, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var88, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var88, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[8]) <= (0.3100337160285562)) {
                    if ((input[6]) <= (0.6911645084619522)) {
                        if ((input[7]) <= (0.6743813455104828)) {
                            memcpy(var88, (double[]){0.75, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var88, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (2552.0)) {
                            memcpy(var88, (double[]){0.0, 0.1152542372881356, 0.8847457627118644, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var88, (double[]){0.0, 0.6812903225806451, 0.31870967741935485, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var88, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[10]) <= (0.04062318056821823)) {
                if ((input[3]) <= (547.2409057617188)) {
                    if ((input[7]) <= (0.544612467288971)) {
                        if ((input[6]) <= (0.4896504580974579)) {
                            memcpy(var88, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var88, (double[]){0.8588235294117647, 0.047058823529411764, 0.011764705882352941, 0.0, 0.0, 0.0, 0.08235294117647059, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[12]) <= (0.08104477450251579)) {
                            memcpy(var88, (double[]){0.9947643979057592, 0.0, 0.0, 0.005235602094240838, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var88, (double[]){0.8333333333333334, 0.0, 0.0, 0.16666666666666666, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[1]) <= (497271.5)) {
                        if ((input[5]) <= (14.5)) {
                            memcpy(var88, (double[]){0.07692307692307693, 0.07692307692307693, 0.0, 0.0, 0.8461538461538461, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var88, (double[]){0.8867924528301887, 0.0, 0.0, 0.0, 0.0, 0.0, 0.11320754716981132, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (259.0)) {
                            memcpy(var88, (double[]){0.975, 0.004807692307692308, 0.0, 0.0, 0.0019230769230769232, 0.0, 0.01826923076923077, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var88, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                memcpy(var88, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var13, var88, 8, var12);
    double var89[8];
    if ((input[13]) <= (0.8354564607143402)) {
        if ((input[8]) <= (0.11366981640458107)) {
            if ((input[5]) <= (8.5)) {
                if ((input[1]) <= (4703.5)) {
                    if ((input[12]) <= (0.8560126721858978)) {
                        if ((input[6]) <= (0.00920245423913002)) {
                            memcpy(var89, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.9666666666666667, 0.0, 0.0, 0.03333333333333333, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[6]) <= (0.8924852013587952)) {
                        if ((input[3]) <= (229.96258544921875)) {
                            memcpy(var89, (double[]){0.009787928221859706, 0.0, 0.0, 0.6557911908646004, 0.0, 0.2732463295269168, 0.0, 0.061174551386623165}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.3925925925925926, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.6074074074074074}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (412.8023376464844)) {
                            memcpy(var89, (double[]){0.0010256410256410256, 0.04, 0.8707692307692307, 0.0, 0.0, 0.0, 0.0, 0.0882051282051282}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.19811320754716982, 0.02830188679245283, 0.0, 0.0, 0.0, 0.0, 0.0, 0.7735849056603774}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[10]) <= (0.04062318056821823)) {
                    if ((input[5]) <= (2450.5)) {
                        if ((input[0]) <= (25549.0)) {
                            memcpy(var89, (double[]){0.969258589511754, 0.0, 0.015069318866787222, 0.007233273056057866, 0.0, 0.008438818565400843, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.0, 0.0, 0.30434782608695654, 0.6956521739130435, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (2275042.0)) {
                            memcpy(var89, (double[]){0.05357142857142857, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9464285714285714, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.9966777408637874, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0033222591362126247, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[9]) <= (0.000015565656212856993)) {
                if ((input[2]) <= (540.2516174316406)) {
                    if ((input[4]) <= (11.5)) {
                        if ((input[1]) <= (51979.0)) {
                            memcpy(var89, (double[]){0.018072289156626505, 0.0, 0.0, 0.0, 0.572289156626506, 0.0, 0.0, 0.40963855421686746}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 0.953307392996109, 0.0, 0.0, 0.04669260700389105}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[4]) <= (16.5)) {
            if ((input[8]) <= (0.0019011406693607569)) {
                if ((input[6]) <= (0.5434599965810776)) {
                    if ((input[10]) <= (0.2799227833747864)) {
                        if ((input[7]) <= (0.9991379380226135)) {
                            memcpy(var89, (double[]){0.8229166666666666, 0.0, 0.0, 0.020833333333333332, 0.0, 0.15625, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[13]) <= (1.1798093914985657)) {
                        if ((input[0]) <= (466.5)) {
                            memcpy(var89, (double[]){0.09090909090909091, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8181818181818182, 0.09090909090909091}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.0, 0.9970149253731343, 0.0, 0.0, 0.0, 0.0, 0.0029850746268656717, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[13]) <= (1.6556861400604248)) {
                            memcpy(var89, (double[]){0.0, 0.4375, 0.0, 0.0, 0.0, 0.0, 0.5625, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.006521739130434782, 0.004347826086956522, 0.0, 0.0, 0.0, 0.0, 0.9652173913043478, 0.02391304347826087}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[6]) <= (0.0009623685182305053)) {
                    memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[10]) <= (0.2766159772872925)) {
                        memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[7]) <= (0.5003138622269034)) {
                if ((input[3]) <= (1.2393182516098022)) {
                    if ((input[1]) <= (124320.0)) {
                        memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[13]) <= (1.0111027359962463)) {
                            memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.0, 0.9523809523809523, 0.0, 0.0, 0.047619047619047616, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[0]) <= (770.5)) {
                        if ((input[0]) <= (754.0)) {
                            memcpy(var89, (double[]){0.0, 0.7142857142857143, 0.0, 0.0, 0.2857142857142857, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[12]) <= (0.002507038996554911)) {
                            memcpy(var89, (double[]){0.0, 0.986328125, 0.0, 0.0, 0.013671875, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var89, (double[]){0.0, 0.7777777777777778, 0.0, 0.0, 0.2222222222222222, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[13]) <= (1.0384615659713745)) {
                    if ((input[2]) <= (356.6841125488281)) {
                        memcpy(var89, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var89, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[4]) <= (248.5)) {
                        memcpy(var89, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var89, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    }
    add_vectors(var12, var89, 8, var11);
    double var90[8];
    if ((input[13]) <= (0.8970217704772949)) {
        if ((input[10]) <= (0.05718035250902176)) {
            if ((input[8]) <= (0.16184448450803757)) {
                if ((input[6]) <= (0.9999293982982635)) {
                    if ((input[4]) <= (112.5)) {
                        if ((input[2]) <= (86.51928329467773)) {
                            memcpy(var90, (double[]){0.4738330975954738, 0.007779349363507779, 0.05233380480905234, 0.157001414427157, 0.0, 0.2545968882602546, 0.054455445544554455, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var90, (double[]){0.9780426599749059, 0.0012547051442910915, 0.0006273525721455458, 0.01066499372647428, 0.0, 0.0018820577164366374, 0.0075282308657465494, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.4172024205327034)) {
                            memcpy(var90, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var90, (double[]){0.03115727002967359, 0.0, 0.0, 0.9688427299703264, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[3]) <= (206.3437271118164)) {
                        if ((input[1]) <= (9169.5)) {
                            memcpy(var90, (double[]){0.1036036036036036, 0.0, 0.16666666666666666, 0.0, 0.0, 0.0, 0.7297297297297297, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var90, (double[]){0.0013477088948787063, 0.02830188679245283, 0.9272237196765498, 0.0, 0.0, 0.0, 0.0431266846361186, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (2711.5)) {
                            memcpy(var90, (double[]){0.5882352941176471, 0.029411764705882353, 0.04411764705882353, 0.0, 0.0, 0.0, 0.3382352941176471, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var90, (double[]){0.9851190476190477, 0.005952380952380952, 0.0, 0.0, 0.0, 0.0, 0.008928571428571428, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[1]) <= (49170.0)) {
                    if ((input[8]) <= (0.580827072262764)) {
                        memcpy(var90, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var90, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var90, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            memcpy(var90, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[5]) <= (1394.5)) {
            if ((input[0]) <= (773.0)) {
                if ((input[5]) <= (12.5)) {
                    if ((input[0]) <= (88.0)) {
                        memcpy(var90, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[4]) <= (43.0)) {
                            memcpy(var90, (double[]){0.017543859649122806, 0.07017543859649122, 0.0, 0.017543859649122806, 0.017543859649122806, 0.17543859649122806, 0.0, 0.7017543859649122}, 8 * sizeof(double));
                        } else {
                            memcpy(var90, (double[]){0.0, 0.17391304347826086, 0.0, 0.4782608695652174, 0.34782608695652173, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[7]) <= (0.9950391948223114)) {
                        if ((input[10]) <= (0.4795081913471222)) {
                            memcpy(var90, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var90, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var90, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[12]) <= (0.512372069992125)) {
                    if ((input[7]) <= (0.03768933657556772)) {
                        if ((input[2]) <= (36.76251983642578)) {
                            memcpy(var90, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var90, (double[]){0.0, 0.9908151549942594, 0.0, 0.0, 0.0, 0.0, 0.0, 0.009184845005740528}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.9990842342376709)) {
                            memcpy(var90, (double[]){0.7674418604651163, 0.0, 0.0, 0.09302325581395349, 0.06976744186046512, 0.0, 0.0, 0.06976744186046512}, 8 * sizeof(double));
                        } else {
                            memcpy(var90, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var90, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[1]) <= (3982764.0)) {
                memcpy(var90, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
            } else {
                memcpy(var90, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var11, var90, 8, var10);
    double var91[8];
    if ((input[6]) <= (0.9390788972377777)) {
        if ((input[0]) <= (125.0)) {
            if ((input[1]) <= (67882.0)) {
                if ((input[13]) <= (0.09232954680919647)) {
                    if ((input[1]) <= (22279.5)) {
                        memcpy(var91, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[4]) <= (3.5)) {
                            memcpy(var91, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.9545454545454546, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.045454545454545456}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[10]) <= (0.3857142925262451)) {
                        if ((input[1]) <= (11020.0)) {
                            memcpy(var91, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.8636363636363636, 0.0, 0.045454545454545456, 0.09090909090909091, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[3]) <= (589.9917602539062)) {
                    if ((input[10]) <= (0.4128440320491791)) {
                        memcpy(var91, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var91, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[8]) <= (0.0933803366497159)) {
                if ((input[10]) <= (0.04062318056821823)) {
                    if ((input[12]) <= (0.417134054005146)) {
                        if ((input[5]) <= (15.0)) {
                            memcpy(var91, (double[]){0.0, 0.0, 0.004415011037527594, 0.9955849889624724, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.9844479004665629, 0.0, 0.0, 0.0015552099533437014, 0.0, 0.0, 0.013996889580093312, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (550.1053466796875)) {
                    if ((input[5]) <= (15.5)) {
                        if ((input[13]) <= (12604.7646484375)) {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.9696641386782232, 0.0, 0.0, 0.030335861321776816}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.4, 0.0, 0.0, 0.6}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (406944.0)) {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        if ((input[3]) <= (212.6202392578125)) {
            if ((input[0]) <= (1647.5)) {
                if ((input[6]) <= (0.98635533452034)) {
                    if ((input[0]) <= (257.0)) {
                        if ((input[13]) <= (0.012944718357175589)) {
                            memcpy(var91, (double[]){0.02702702702702703, 0.0, 0.08108108108108109, 0.0, 0.0, 0.0, 0.8648648648648649, 0.02702702702702703}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (5.5)) {
                            memcpy(var91, (double[]){0.0, 0.058823529411764705, 0.14705882352941177, 0.0, 0.0, 0.0, 0.08823529411764706, 0.7058823529411765}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.21428571428571427, 0.5714285714285714, 0.0, 0.0, 0.0, 0.21428571428571427, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[13]) <= (1.937172770500183)) {
                        if ((input[5]) <= (1262.5)) {
                            memcpy(var91, (double[]){0.05671077504725898, 0.20982986767485823, 0.5406427221172023, 0.0, 0.0, 0.0, 0.0, 0.19281663516068054}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (51.08372116088867)) {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.034482758620689655, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9655172413793104, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[3]) <= (0.6390270888805389)) {
                    if ((input[4]) <= (34461.5)) {
                        if ((input[13]) <= (0.5008478034287691)) {
                            memcpy(var91, (double[]){0.0, 0.04132231404958678, 0.9586776859504132, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (40.000057220458984)) {
                            memcpy(var91, (double[]){0.0, 0.08571428571428572, 0.9142857142857143, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.4117647058823529, 0.5882352941176471, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[4]) <= (21746.5)) {
                        if ((input[5]) <= (138348.5)) {
                            memcpy(var91, (double[]){0.0, 0.8604954367666232, 0.1395045632333768, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[13]) <= (0.751888996528578)) {
                            memcpy(var91, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[2]) <= (969.908447265625)) {
                if ((input[10]) <= (0.128031387925148)) {
                    if ((input[0]) <= (2670.0)) {
                        if ((input[5]) <= (2501.0)) {
                            memcpy(var91, (double[]){0.8615384615384616, 0.06153846153846154, 0.07692307692307693, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (4082.0)) {
                            memcpy(var91, (double[]){0.9852941176470589, 0.0, 0.0, 0.0, 0.0, 0.0, 0.014705882352941176, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[1]) <= (2729195.5)) {
                    if ((input[1]) <= (2688968.5)) {
                        if ((input[3]) <= (1233.6180725097656)) {
                            memcpy(var91, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var91, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var91, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var10, var91, 8, var9);
    double var92[8];
    if ((input[10]) <= (0.04062318056821823)) {
        if ((input[3]) <= (125.33894348144531)) {
            if ((input[6]) <= (0.8684550821781158)) {
                if ((input[0]) <= (143.5)) {
                    if ((input[6]) <= (0.003496503457427025)) {
                        memcpy(var92, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[9]) <= (0.6465035080909729)) {
                            memcpy(var92, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (0.5)) {
                        if ((input[0]) <= (1969.0)) {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 0.22794117647058823, 0.7720588235294118, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (0.2144838273525238)) {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.9693877551020408, 0.030612244897959183, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.036544850498338874, 0.0, 0.0, 0.4398671096345515, 0.38073089700996676, 0.14285714285714285, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[13]) <= (0.08630717545747757)) {
                    if ((input[5]) <= (1274.5)) {
                        if ((input[7]) <= (0.09238709509372711)) {
                            memcpy(var92, (double[]){0.011454753722794959, 0.03665521191294387, 0.9518900343642611, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[5]) <= (1261.0)) {
                        if ((input[13]) <= (0.6270627230405807)) {
                            memcpy(var92, (double[]){0.5, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.003386004514672686, 0.9966139954853274, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[5]) <= (8.5)) {
                if ((input[2]) <= (133.92166900634766)) {
                    if ((input[12]) <= (0.4649474546313286)) {
                        if ((input[4]) <= (626.0)) {
                            memcpy(var92, (double[]){0.0, 0.04040404040404041, 0.1414141414141414, 0.16161616161616163, 0.6565656565656566, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (340.8895568847656)) {
                        memcpy(var92, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[8]) <= (0.10521500557661057)) {
                            memcpy(var92, (double[]){0.8769230769230769, 0.07692307692307693, 0.046153846153846156, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[5]) <= (2652.5)) {
                    if ((input[9]) <= (0.031547619961202145)) {
                        if ((input[2]) <= (55.808515548706055)) {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.14285714285714285, 0.8571428571428571, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.9780426599749059, 0.0, 0.00439146800501882, 0.0012547051442910915, 0.015056461731493099, 0.0, 0.0012547051442910915, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[9]) <= (0.2771871406584978)) {
                            memcpy(var92, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[13]) <= (0.009635585360229015)) {
                        if ((input[4]) <= (9.0)) {
                            memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[0]) <= (1096.5)) {
                            memcpy(var92, (double[]){0.02247191011235955, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9775280898876404, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var92, (double[]){0.9126984126984127, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0873015873015873, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    } else {
        memcpy(var92, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var9, var92, 8, var8);
    double var93[8];
    if ((input[2]) <= (110.0625)) {
        if ((input[2]) <= (13.982586860656738)) {
            memcpy(var93, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
        } else {
            if ((input[13]) <= (0.8756542503833771)) {
                if ((input[8]) <= (0.3114401998464018)) {
                    if ((input[2]) <= (39.36739158630371)) {
                        if ((input[9]) <= (0.3621397032402456)) {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (1412.0)) {
                            memcpy(var93, (double[]){0.08703071672354949, 0.02104664391353811, 0.5221843003412969, 0.21046643913538113, 0.0, 0.01763367463026166, 0.0, 0.1416382252559727}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[1]) <= (47396.5)) {
                        if ((input[10]) <= (0.3859890103340149)) {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[6]) <= (0.5168434157967567)) {
                    if ((input[8]) <= (0.4573829472064972)) {
                        if ((input[7]) <= (0.44563374668359756)) {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.019230769230769232, 0.0, 0.0, 0.8653846153846154, 0.0, 0.0, 0.0, 0.11538461538461539}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[1]) <= (25967.5)) {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.4666666666666667, 0.0, 0.0, 0.5333333333333333}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (41.91147804260254)) {
                        if ((input[5]) <= (1358.5)) {
                            memcpy(var93, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (58.27493476867676)) {
                            memcpy(var93, (double[]){0.005820721769499418, 0.8416763678696159, 0.0, 0.0, 0.0, 0.0, 0.14551804423748546, 0.006984866123399301}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.14678899082568808, 0.0, 0.0, 0.0, 0.0, 0.8532110091743119, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        }
    } else {
        if ((input[5]) <= (8.5)) {
            if ((input[1]) <= (47090.0)) {
                if ((input[8]) <= (0.3571428656578064)) {
                    if ((input[0]) <= (135.5)) {
                        memcpy(var93, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[4]) <= (43.0)) {
                            memcpy(var93, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[4]) <= (4.5)) {
                    if ((input[3]) <= (474.84605407714844)) {
                        if ((input[1]) <= (69680.0)) {
                            memcpy(var93, (double[]){0.3333333333333333, 0.0, 0.0, 0.0, 0.6666666666666666, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0034965034965034965, 0.0, 0.0, 0.0, 0.017482517482517484, 0.0, 0.0, 0.9790209790209791}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[5]) <= (3.5)) {
                            memcpy(var93, (double[]){0.0625, 0.0625, 0.0, 0.0, 0.4375, 0.0, 0.0, 0.4375}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.8947368421052632, 0.0, 0.0, 0.0, 0.10526315789473684, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (148.5572280883789)) {
                        if ((input[3]) <= (204.22957611083984)) {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.8666442334651947)) {
                            memcpy(var93, (double[]){0.07142857142857142, 0.0, 0.017857142857142856, 0.0, 0.9107142857142857, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[6]) <= (0.9973130822181702)) {
                if ((input[1]) <= (62098.5)) {
                    if ((input[8]) <= (0.48163843154907227)) {
                        if ((input[4]) <= (77.5)) {
                            memcpy(var93, (double[]){0.9769503546099291, 0.0017730496453900709, 0.005319148936170213, 0.0, 0.0, 0.0, 0.0035460992907801418, 0.012411347517730497}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (690.0346374511719)) {
                        if ((input[0]) <= (1451.0)) {
                            memcpy(var93, (double[]){0.5446224256292906, 0.0, 0.0, 0.0, 0.02745995423340961, 0.011441647597254004, 0.006864988558352402, 0.4096109839816934}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.963882618510158, 0.0, 0.0, 0.002257336343115124, 0.02708803611738149, 0.0, 0.006772009029345372, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[5]) <= (5330.0)) {
                    if ((input[1]) <= (386492.0)) {
                        if ((input[1]) <= (208482.0)) {
                            memcpy(var93, (double[]){0.7368421052631579, 0.0, 0.05263157894736842, 0.0, 0.0, 0.0, 0.21052631578947367, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.09523809523809523, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9047619047619048}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[10]) <= (0.4966358244419098)) {
                            memcpy(var93, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[13]) <= (0.014708434347994626)) {
                        memcpy(var93, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var93, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    }
    add_vectors(var8, var93, 8, var7);
    double var94[8];
    if ((input[10]) <= (0.04062318056821823)) {
        if ((input[3]) <= (115.03159713745117)) {
            if ((input[7]) <= (0.8897569477558136)) {
                if ((input[13]) <= (0.7937293946743011)) {
                    if ((input[0]) <= (104.5)) {
                        memcpy(var94, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[5]) <= (1260.0)) {
                            memcpy(var94, (double[]){0.0, 0.01895991332611051, 0.4761646803900325, 0.0005417118093174431, 0.3250270855904659, 0.17930660888407368, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var94, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (1282.0)) {
                        if ((input[8]) <= (0.4659873319324106)) {
                            memcpy(var94, (double[]){0.006787330316742082, 0.9739819004524887, 0.0, 0.0, 0.0, 0.019230769230769232, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var94, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var94, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[0]) <= (153.0)) {
                    memcpy(var94, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[2]) <= (123.73940658569336)) {
                        memcpy(var94, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[3]) <= (55.174442291259766)) {
                            memcpy(var94, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var94, (double[]){0.8823529411764706, 0.0, 0.0, 0.11764705882352941, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            if ((input[8]) <= (0.16184448450803757)) {
                if ((input[9]) <= (0.3403689283877611)) {
                    if ((input[4]) <= (116.5)) {
                        if ((input[7]) <= (0.11280433088541031)) {
                            memcpy(var94, (double[]){0.8828571428571429, 0.008571428571428572, 0.008571428571428572, 0.0, 0.0, 0.0, 0.1, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var94, (double[]){0.9903194578896418, 0.0, 0.000968054211035818, 0.006776379477250726, 0.0, 0.0, 0.001936108422071636, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[7]) <= (0.9889377951622009)) {
                            memcpy(var94, (double[]){0.0, 0.09375, 0.28125, 0.625, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var94, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var94, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[3]) <= (127.99693298339844)) {
                    if ((input[5]) <= (45.0)) {
                        memcpy(var94, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var94, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var94, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        memcpy(var94, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var7, var94, 8, var6);
    double var95[8];
    if ((input[13]) <= (0.8367486298084259)) {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[2]) <= (86.50704574584961)) {
                if ((input[8]) <= (0.3639143705368042)) {
                    if ((input[2]) <= (14.0)) {
                        memcpy(var95, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[9]) <= (0.5065217316150665)) {
                            memcpy(var95, (double[]){0.036354581673306775, 0.025896414342629483, 0.44123505976095617, 0.3655378486055777, 0.0, 0.0, 0.13097609561752988, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[7]) <= (0.7331600487232208)) {
                    if ((input[6]) <= (0.20187541842460632)) {
                        memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[8]) <= (0.38443224132061005)) {
                            memcpy(var95, (double[]){0.9625334522747547, 0.003568242640499554, 0.006244424620874219, 0.001784121320249777, 0.0026761819803746653, 0.0026761819803746653, 0.020517395182872437, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[1]) <= (17183.5)) {
                        memcpy(var95, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[2]) <= (148.01477813720703)) {
                            memcpy(var95, (double[]){0.3684210526315789, 0.0, 0.0, 0.631578947368421, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var95, (double[]){0.9908088235294118, 0.0, 0.0, 0.0055147058823529415, 0.003676470588235294, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[4]) <= (15.5)) {
            if ((input[2]) <= (49.51627159118652)) {
                if ((input[6]) <= (0.5026369467377663)) {
                    if ((input[8]) <= (0.48346054553985596)) {
                        if ((input[12]) <= (0.48765432834625244)) {
                            memcpy(var95, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[5]) <= (1254.0)) {
                        memcpy(var95, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[5]) <= (13.5)) {
                    if ((input[10]) <= (0.2766159772872925)) {
                        if ((input[7]) <= (0.05655714590102434)) {
                            memcpy(var95, (double[]){0.007434944237918215, 0.9925650557620818, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var95, (double[]){0.2, 0.0, 0.0, 0.6666666666666666, 0.13333333333333333, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[5]) <= (1913.0)) {
                        if ((input[8]) <= (0.49254903197288513)) {
                            memcpy(var95, (double[]){0.9428571428571428, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.05714285714285714}, 8 * sizeof(double));
                        } else {
                            memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[1]) <= (7058159.0)) {
                if ((input[6]) <= (0.5058309184387326)) {
                    if ((input[7]) <= (0.5154807921499014)) {
                        memcpy(var95, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var95, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var95, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var95, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        }
    }
    add_vectors(var6, var95, 8, var5);
    double var96[8];
    if ((input[13]) <= (0.8970217704772949)) {
        if ((input[8]) <= (0.12134403735399246)) {
            if ((input[4]) <= (112.0)) {
                if ((input[12]) <= (0.4879879802465439)) {
                    if ((input[0]) <= (130.5)) {
                        if ((input[1]) <= (72626.5)) {
                            memcpy(var96, (double[]){0.9908864954432477, 0.0, 0.0008285004142502071, 0.0, 0.0, 0.0, 0.0, 0.008285004142502071}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.6666666666666666, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.3333333333333333}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (4.5)) {
                            memcpy(var96, (double[]){0.10355029585798817, 0.03994082840236687, 0.2729289940828402, 0.09319526627218935, 0.0, 0.0, 0.16715976331360946, 0.32322485207100593}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.7720815318097591, 0.0024706609017912293, 0.027177269919703522, 0.04879555281037678, 0.0, 0.0, 0.053119209388511425, 0.09635577516985794}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[7]) <= (0.4122302904725075)) {
                    memcpy(var96, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[4]) <= (146.5)) {
                        if ((input[3]) <= (449.84242248535156)) {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var96, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[10]) <= (0.11747343838214874)) {
                if ((input[12]) <= (0.03773357532918453)) {
                    if ((input[0]) <= (144.0)) {
                        memcpy(var96, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var96, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[0]) <= (1695.5)) {
            if ((input[0]) <= (293.5)) {
                if ((input[5]) <= (1322.0)) {
                    if ((input[12]) <= (0.5101033076643944)) {
                        if ((input[2]) <= (577.7424926757812)) {
                            memcpy(var96, (double[]){0.72, 0.0, 0.0, 0.24, 0.04, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[2]) <= (42.680315017700195)) {
                    if ((input[6]) <= (0.5056073446758091)) {
                        if ((input[8]) <= (0.49607330560684204)) {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.5714285714285714, 0.0, 0.42857142857142855, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (42.02787208557129)) {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.0, 0.1111111111111111, 0.0, 0.0, 0.0, 0.0, 0.8888888888888888, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[10]) <= (0.2271309792995453)) {
                        if ((input[5]) <= (24.5)) {
                            memcpy(var96, (double[]){0.0, 0.9857142857142858, 0.0, 0.0, 0.007142857142857143, 0.007142857142857143, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.2833333333333333, 0.0, 0.0, 0.0, 0.0, 0.0, 0.7166666666666667, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[4]) <= (117.0)) {
                if ((input[5]) <= (30.5)) {
                    if ((input[0]) <= (31003.5)) {
                        if ((input[2]) <= (65.53940010070801)) {
                            memcpy(var96, (double[]){0.0, 0.9695652173913043, 0.0, 0.0, 0.030434782608695653, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.0, 0.1111111111111111, 0.0, 0.8888888888888888, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[8]) <= (0.49987345933914185)) {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[2]) <= (253.6078586578369)) {
                        memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var96, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[13]) <= (1.0040134191513062)) {
                    if ((input[12]) <= (0.0023865728871896863)) {
                        if ((input[3]) <= (20.617850303649902)) {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.8292682926829268, 0.17073170731707318, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[8]) <= (0.5000773867068347)) {
                        if ((input[13]) <= (24434.7646484375)) {
                            memcpy(var96, (double[]){0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var96, (double[]){0.0, 0.9473684210526315, 0.0, 0.05263157894736842, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var96, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            }
        }
    }
    add_vectors(var5, var96, 8, var4);
    double var97[8];
    if ((input[8]) <= (0.13800188899040222)) {
        if ((input[10]) <= (0.04062318056821823)) {
            if ((input[4]) <= (118.5)) {
                if ((input[3]) <= (103.28609848022461)) {
                    if ((input[12]) <= (0.5565217286348343)) {
                        if ((input[6]) <= (0.9310224056243896)) {
                            memcpy(var97, (double[]){0.7757510729613734, 0.0, 0.0, 0.22424892703862662, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){0.015309672929714684, 0.27279053583855256, 0.28462073764787754, 0.0, 0.0, 0.0, 0.42727905358385526, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[12]) <= (0.4776517152786255)) {
                        if ((input[2]) <= (103.72270202636719)) {
                            memcpy(var97, (double[]){0.3055555555555556, 0.011111111111111112, 0.07222222222222222, 0.12777777777777777, 0.0, 0.0, 0.48333333333333334, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){0.972768532526475, 0.0015128593040847202, 0.0030257186081694403, 0.0005042864346949068, 0.0, 0.0, 0.022188603126575897, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[2]) <= (261.24562072753906)) {
                            memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[0]) <= (5708.5)) {
                    if ((input[0]) <= (759.5)) {
                        if ((input[7]) <= (0.3857666105031967)) {
                            memcpy(var97, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[9]) <= (0.001285922946408391)) {
                            memcpy(var97, (double[]){0.0, 0.10918544194107452, 0.2027729636048527, 0.6880415944540728, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[6]) <= (0.5042211855761707)) {
                        if ((input[4]) <= (1550.5)) {
                            memcpy(var97, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (1.3510217070579529)) {
                            memcpy(var97, (double[]){0.0, 0.21153846153846154, 0.7884615384615384, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){0.0, 0.8973880597014925, 0.10261194029850747, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                }
            }
        } else {
            memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
        }
    } else {
        if ((input[4]) <= (49.5)) {
            if ((input[0]) <= (758.0)) {
                if ((input[2]) <= (44.45919227600098)) {
                    memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    if ((input[7]) <= (0.24441590160131454)) {
                        if ((input[0]) <= (707.5)) {
                            memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 0.02403846153846154, 0.0, 0.0, 0.9759615384615384}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[3]) <= (463.6087188720703)) {
                            memcpy(var97, (double[]){0.4444444444444444, 0.0, 0.0, 0.0, 0.5555555555555556, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    }
                }
            } else {
                if ((input[10]) <= (0.13105924427509308)) {
                    memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                }
            }
        } else {
            memcpy(var97, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
        }
    }
    add_vectors(var4, var97, 8, var3);
    double var98[8];
    if ((input[5]) <= (15.5)) {
        if ((input[13]) <= (0.8756542503833771)) {
            if ((input[0]) <= (128.5)) {
                if ((input[13]) <= (0.4166666716337204)) {
                    if ((input[10]) <= (0.4128440320491791)) {
                        if ((input[13]) <= (0.08533653989434242)) {
                            memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.875, 0.0, 0.0, 0.125, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[0]) <= (60.0)) {
                        memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[9]) <= (0.34298195876181126)) {
                    if ((input[8]) <= (0.10521500557661057)) {
                        if ((input[10]) <= (0.16251353919506073)) {
                            memcpy(var98, (double[]){0.0212882096069869, 0.025655021834061136, 0.4868995633187773, 0.4661572052401747, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[4]) <= (3.5)) {
                            memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.4854771784232365, 0.0, 0.0, 0.5145228215767634}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.9533678756476683, 0.0, 0.0, 0.046632124352331605}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        } else {
            if ((input[10]) <= (0.2383333295583725)) {
                if ((input[8]) <= (0.4835737829998834)) {
                    if ((input[9]) <= (0.004453405039384961)) {
                        if ((input[13]) <= (1.0002058744430542)) {
                            memcpy(var98, (double[]){0.010752688172043012, 0.8530465949820788, 0.0, 0.13620071684587814, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.006269592476489028, 0.9780564263322884, 0.0, 0.01567398119122257, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        if ((input[6]) <= (0.004519097274169326)) {
                            memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.2857142857142857, 0.0, 0.7142857142857143, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
            }
        }
    } else {
        if ((input[5]) <= (2450.5)) {
            if ((input[6]) <= (0.9963043034076691)) {
                if ((input[4]) <= (6.5)) {
                    if ((input[12]) <= (0.00012735609197989106)) {
                        if ((input[3]) <= (322.20361328125)) {
                            memcpy(var98, (double[]){0.7978142076502732, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.20218579234972678}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.49230769230769234, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5076923076923077}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[10]) <= (0.06565086543560028)) {
                        if ((input[2]) <= (56.731807708740234)) {
                            memcpy(var98, (double[]){0.0, 0.0, 0.4, 0.0, 0.4, 0.2, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.9904397705544933, 0.0, 0.0, 0.0, 0.0057361376673040155, 0.0038240917782026767, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[13]) <= (0.027010749094188213)) {
                    if ((input[5]) <= (42.5)) {
                        if ((input[3]) <= (500.4667053222656)) {
                            memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.9714285714285714, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.02857142857142857}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    if ((input[3]) <= (560.7469482421875)) {
                        memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
                    }
                }
            }
        } else {
            if ((input[1]) <= (3266548.0)) {
                if ((input[8]) <= (0.0012224939418956637)) {
                    if ((input[6]) <= (0.5415588021278381)) {
                        memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[1]) <= (2275401.5)) {
                            memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var98, (double[]){0.3333333333333333, 0.0, 0.0, 0.0, 0.0, 0.0, 0.6666666666666666, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                if ((input[1]) <= (6842693.0)) {
                    if ((input[1]) <= (6810778.5)) {
                        memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        memcpy(var98, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var98, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    }
    add_vectors(var3, var98, 8, var2);
    double var99[8];
    if ((input[10]) <= (0.04062318056821823)) {
        if ((input[2]) <= (86.50704574584961)) {
            if ((input[8]) <= (0.36459649878088385)) {
                if ((input[7]) <= (0.8762498199939728)) {
                    if ((input[5]) <= (1562.5)) {
                        if ((input[1]) <= (3807.0)) {
                            memcpy(var99, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var99, (double[]){0.016902695294655094, 0.41480127912288717, 0.39104613978985836, 0.002740977615349475, 0.0, 0.1745089081772499, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var99, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0}, 8 * sizeof(double));
                    }
                } else {
                    memcpy(var99, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            } else {
                memcpy(var99, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
            }
        } else {
            if ((input[8]) <= (0.16184448450803757)) {
                if ((input[4]) <= (118.5)) {
                    if ((input[3]) <= (14.595741748809814)) {
                        memcpy(var99, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    } else {
                        if ((input[12]) <= (0.5081395208835602)) {
                            memcpy(var99, (double[]){0.9670014347202296, 0.0023912003825920613, 0.0028694404591104736, 0.003347680535628886, 0.0, 0.0, 0.024390243902439025, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var99, (double[]){0.42857142857142855, 0.0, 0.0, 0.0, 0.0, 0.5714285714285714, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    }
                } else {
                    if ((input[5]) <= (5947.5)) {
                        if ((input[6]) <= (0.6065411493182182)) {
                            memcpy(var99, (double[]){0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        } else {
                            memcpy(var99, (double[]){0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                        }
                    } else {
                        memcpy(var99, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                    }
                }
            } else {
                if ((input[0]) <= (168.0)) {
                    memcpy(var99, (double[]){1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                } else {
                    memcpy(var99, (double[]){0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0}, 8 * sizeof(double));
                }
            }
        }
    } else {
        memcpy(var99, (double[]){0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0}, 8 * sizeof(double));
    }
    add_vectors(var2, var99, 8, var1);
    mul_vector_number(var1, 0.02, 8, var0);
    memcpy(output, var0, 8 * sizeof(double));
}

static int ensure_capacity(void **array_ptr, size_t *count, size_t *capacity, size_t elem_size) {
    if (*count < *capacity) {
        return 0;
    }

    size_t new_capacity = (*capacity) ? (*capacity) * 2 : INITIAL_SIZE;

    void *new_array = realloc(*array_ptr, new_capacity * elem_size);
    if (!new_array) {
        fprintf(stderr, "Error: realloc failed (requested %zu bytes)\n", new_capacity * elem_size);
        return -1;
    }

    *array_ptr = new_array;
    *capacity = new_capacity;
    return 0;
}

void init_window_stat(Packet_Window *window){
    // 务必先释放window中已分配的地址资源
    free(window->src_ips);
    free(window->dst_ports);
    free(window->packet_sizes);

    memset(window, 0, sizeof(Packet_Window));

    window->src_ips = calloc(INITIAL_SIZE, sizeof(uint32_t));
    window->dst_ports = calloc(INITIAL_SIZE, sizeof(uint16_t));
    window->packet_sizes = calloc(INITIAL_SIZE, sizeof(uint16_t));

    window->ips_capacity = INITIAL_SIZE;
    window->ports_capacity = INITIAL_SIZE;
    window->sizes_capacity = INITIAL_SIZE;

    window->ips_count = 0;
    window->ports_count = 0;
    window->sizes_count = 0;
}

int is_private_ip(uint32_t ip, uint32_t local_ip, uint32_t mask){
    if ((ip & mask) == (local_ip & mask)) {
        return 1;
    }
    uint32_t ip_h = ntohl(ip);

    // 224.0.0.0/4 (multicast: 224–239)
    if ((ip_h >> 28) == 0xE) {
        return 1;
    }
    // 127.0.0.0/8 (loopback)
    if ((ip_h >> 24) == 0x7F) {
        return 1;
    }
    return 0;
}

int get_interface_ip(const char *iface, uint32_t *ip_out) {
    struct ifaddrs *ifaddrs_ptr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddrs_ptr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (strcmp(ifa->ifa_name, iface) != 0) continue;

        // 只处理 IPv4
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            *ip_out = ntohl(sin->sin_addr.s_addr);
            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddrs_ptr);
    return found ? 0 : -1;
}

int is_multicast(uint32_t ip){
    uint32_t ip_h = ntohl(ip);
    if ((ip_h >> 28) == 0xE) {
        return 1;
    }
    return 0;
}

int add_src_ip(Packet_Window *win, uint32_t ip) {
    if (ensure_capacity((void**)&win->src_ips, &win->ips_count, &win->ips_capacity, sizeof(uint32_t)) != 0) {
        return -1;
    }
    win->src_ips[win->ips_count++] = ip;
    return 0;
}

int add_dst_port(Packet_Window *win, uint16_t port) {
    if (ensure_capacity((void**)&win->dst_ports, &win->ports_count, &win->ports_capacity, sizeof(uint16_t)) != 0) {
        return -1;
    }
    win->dst_ports[win->ports_count++] = port;
    return 0;
}

int add_packet_size(Packet_Window *win, uint16_t size) {
    if (ensure_capacity((void**)&win->packet_sizes, &win->sizes_count, &win->sizes_capacity, sizeof(uint16_t)) != 0) {
        return -1;
    }
    win->packet_sizes[win->sizes_count++] = size;
    return 0;
}

int compare_uint32(const void *a, const void *b) {
    uint32_t val_a = *(const uint32_t *)a;
    uint32_t val_b = *(const uint32_t *)b;
    if (val_a < val_b) return -1;
    if (val_a > val_b) return 1;
    return 0;
}

int compare_uint16(const void *a, const void *b) {
    uint16_t val_a = *(const uint16_t *)a;
    uint16_t val_b = *(const uint16_t *)b;
    if (val_a < val_b) return -1;
    if (val_a > val_b) return 1;
    return 0;
}

int count_unique_ips(uint32_t *src_ips, size_t ips_count) {
    if (ips_count == 0) return 0;
    
    uint32_t *sorted_ips = malloc(ips_count * sizeof(uint32_t));
    if (!sorted_ips) return 0;
    
    for (size_t i = 0; i < ips_count; i++) {
        sorted_ips[i] = src_ips[i];
    }
    
    qsort(sorted_ips, ips_count, sizeof(uint32_t), compare_uint32);
    
    int unique_count = 1;
    
    for (size_t i = 1; i < ips_count; i++) {
        if (sorted_ips[i] != sorted_ips[i - 1]) {
            unique_count++;
        }
    }
    
    free(sorted_ips);
    return unique_count;
}

int count_unique_ports(uint16_t *dst_ports, size_t ports_count){
    if (ports_count == 0) return 0;

    uint16_t *sorted_ports = malloc(ports_count * sizeof(uint16_t));
    if (!sorted_ports) return 0;

    for (size_t i = 0; i < ports_count; i++) {
        sorted_ports[i] = dst_ports[i];
    }

    qsort(sorted_ports, ports_count, sizeof(uint16_t), compare_uint16);
    
    int unique_count = 1;
    
    for (size_t i = 1; i < ports_count; i++) {
        if (sorted_ports[i] != sorted_ports[i - 1]) {
            unique_count++;
        }
    }
    
    free(sorted_ports);
    return unique_count;
}

int analyze_and_update_win(Packet_Window *win, char* buffer, uint32_t *local_ip, int max_packets){
    if(win->p_count >= max_packets){
        return -1;
    }

    uint16_t ether_type = ntohs(*(uint16_t*)(buffer + 12));
    if (ether_type != ETH_P_IP){
        return -1;
    }

    struct iphdr *ip_hdr = (struct iphdr*)(buffer + 14);
    if (ip_hdr->version != 4){
        return -1;
    }

    uint16_t ip_hl = ip_hdr->ihl * 4; // 实际IP头的长度
    uint16_t total_len = ntohs(ip_hdr->tot_len); // 整个IP包的长度

    uint32_t ip_src = ntohl(ip_hdr->saddr);
    uint32_t ip_dst = ntohl(ip_hdr->daddr);
    uint32_t netmask = MASK_24;
    
    int ip_src_location = is_private_ip(ip_src, *local_ip, netmask);
    int ip_dst_location = is_private_ip(ip_dst, *local_ip, netmask);

    if(ip_src_location == 1 && ip_dst_location == 0){
        win->uplink_packet_count += 1;
        win->upload_payload_len += (total_len - ip_hl);
    }else if(ip_dst_location == 1 && ip_src_location == 0){
        win->downlink_packet_count += 1;
        win->download_payload_len += (total_len - ip_hl);
    }else if(ip_dst_location == 0 && ip_src_location == 0){
        return -1;
    }

    win->p_count++;
    add_packet_size(win, total_len);
    add_src_ip(win, ip_src);

    // 检查是否是广播/组播
    if(ip_dst == 0xFFFFFFFF){
        win->broadcast_count++;
    }else if(is_multicast(ip_dst) == 1){
        win->multicast_count++;
    }

    // 检查分片
    __u16 frag_off = ntohs(ip_hdr -> frag_off);
    __u16 frag_offset = frag_off & 0x1FFF;
    int MF_set = frag_off & 0x2000;
    if (frag_offset != 0 || MF_set != 0){
        win->fragment_count++;
    }

    uint8_t protocol = ip_hdr->protocol;
    uint16_t transport_offset = 14 + ip_hl;
    if (protocol == IPPROTO_TCP){
        win->tcp_count++;
        // 解析tcp载荷
        uint8_t *tcp_bytes = (uint8_t*)(buffer + transport_offset);
        uint16_t dst_port = ntohs(*(uint16_t*)(tcp_bytes + 2));

        if(*local_ip == ip_dst){
            add_dst_port(win, dst_port);
        }
        uint8_t flags = tcp_bytes[13];
        // uint16_t fin = flags & 0x01;
        uint16_t syn = flags & 0x02;
        // uint16_t rst = flags & 0x04;
        // uint16_t psh = flags & 0x08;
        uint16_t ack = flags & 0x10;
        // uint16_t urg = flags & 0x20;
        if(ack!=0){
            win->ack_count++;
        }if(syn!=0){
            win->syn_count++;
        }
    }else if(protocol == IPPROTO_UDP){
        win->udp_count++;
        uint16_t dest_port = ntohs(*(uint16_t*)(buffer + transport_offset + 2));
        add_dst_port(win, dest_port);
    }else if(protocol == IPPROTO_ICMP){
        win->icmp_count++;
    }else if(protocol == IPPROTO_IGMP){
        win->igmp_count++;
    }
}

int compute_feature(Packet_Window *win, double* features, uint8_t timeval){
    // features[0] = (double)win->p_count/(double)timeval;//F1 packets_per_sec
    uint64_t total_ip_len = 0; 
    for(int i = 0; i<win->sizes_count; i++){
        uint16_t size = win->packet_sizes[i];
        total_ip_len += size;
    }
    // features[1] = (double)total_ip_len;//F2 total_bytes
    features[0] = win->p_count/(double)timeval;//F3 packets_per_sec
    features[1] = (double)total_ip_len/(double)timeval;//F4 bytes_per_sec
    if(win->p_count > 0){
        features[2]= (double)total_ip_len/(double)win->p_count;//F5 avg_packet_size
    }
    else{
        features[2] = 0.0;
    }
    if(win->sizes_count == 0){
        features[3] = 0.0;//F6 std_packet_size 
    }else{
        double mean = (double)total_ip_len / (double)win->sizes_count;
        double variance = 0.0;
        for (int i = 0; i < win->sizes_count; i++) {
            uint16_t size = win->packet_sizes[i];
            double diff = (double)size - mean;
            variance += diff * diff;
        }
        variance /= (double)win->sizes_count;  // 总体标准差
        features[3] = sqrt(variance); //F6 std_packet_size //后续要加上sqrt()
        }
    
    features[4] = count_unique_ips(win->src_ips, win->ips_count);  //F7
    features[5] = count_unique_ports(win->dst_ports, win->ports_count);  //F8

    if(win->p_count == 0){
        win->p_count = 1; 
    }
    features[6] = (double)win->tcp_count/(double)win->p_count;//F9 ratio_tcp
    features[7] = (double)win->udp_count/(double)win->p_count;//F10 ratio_udp
    features[8] = (double)win->icmp_count/(double)win->p_count;//F11 ratio_icmp
    features[9] = (double)win->igmp_count/(double)win->p_count;//F12 ratio_igmp
    features[10] = (double)win->fragment_count/(double)win->p_count;//F13 ratio_fragment
    features[11] = (double)win->broadcast_count/(double)win->p_count;//F14 ratio_broadcast
    features[12] = (double)win->multicast_count/(double)win->p_count;//F15 ratio_multicast
    features[13] = (double)win->syn_count/(double)win->p_count;//F16 syn_count_ratio
    features[14] = (double)win->ack_count/(double)win->p_count;//F17 ack_count_ratio
    if(win->syn_count == 0){
        features[15] = 0;
    }else if(win->ack_count == 0){
        features[15] = 25337.738800000025;//根据训练数据的99.9上分位数，将无穷大替换为MAX_VALUE*1.1
    }else{
        features[15] = (double)win->syn_count/(double)win->ack_count;//F18 syn_ack_ratio  
    }
    // features[18] = (double)win->uplink_packet_count/(double)win->p_count;//F19 uplink_packet_count
    // features[19] = (double)win->uplink_packet_count/((double)win->downlink_packet_count+0.000001);//F20 uplink_downlink_count_ratio
    // features[20] = (double)win->upload_payload_len;//F21 upload_payload_len
    // features[21] = (double)win->upload_payload_len/((double)win->download_payload_len+0.000001);//F22 upload_download_len_ratio
}

int argmax(double *arr, int size) {
    int best_index = 0;
    double best_value = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] > best_value) {
            best_value = arr[i];
            best_index = i;
        }
    }
    return best_index;
}

int predict(double* features){
    // return 0;
    double scores[LABELS_NUM];
    score(features, scores);
    return argmax(scores, LABELS_NUM);
}

int main(int argc, char *argv[]){
    char *iface = NULL;
    int block_num = BLOCK_NR;
    int max_packets = MAX_PACKETS;
    int win_len = WIN_LEN;

    int opt;
     while ((opt = getopt(argc, argv, "i:b:m:t:h")) != -1) {
        switch (opt) {
            case 'i':
                iface = optarg;
                break;
            case 'b':
                block_num = atoi(optarg);
                break;
            case 'm':
                max_packets = atoi(optarg);
                break;
            case 't':
                win_len = atoi(optarg);
                break;
            case 'h':
                printf("Usage: %s -i <interface> [-b <block_num>]\n", argv[0]);
                printf("  -i, --interface   Network interface (e.g., eth0)\n");
                printf("  -b, --block_num   Number of blocks (default: 8)\n");
                printf("  -m, --max_packets   Maximum number of packets in a time window.(default: 5000)\n");
                printf("  -t, --win_len   Length of traffic time window.(default:1 second)\n");
                printf("  -h, --help        Show this help\n");
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "Try '%s -h' for help.\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (iface == NULL) {
        fprintf(stderr, "Error: -i <interface> is required.\n");
        fprintf(stderr, "Try '%s -h' for help.\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1){
        perror("socket error");
        return -1;
    }

    int version = TPACKET_V3;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0){
        perror("setsockopt PACKET_VERSION");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 环形缓冲区的设置参数
    struct tpacket_req3 req  = {
        .tp_block_size = BLOCK_SIZE,
        .tp_frame_size = FRAME_SIZE,
        .tp_block_nr   = block_num,
        .tp_frame_nr   = (BLOCK_SIZE * block_num) / FRAME_SIZE,
        .tp_retire_blk_tov = 100,
        .tp_sizeof_priv = 0,
        .tp_feature_req_word = 0
    };

    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        perror("setsockopt PACKET_RX_RING");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 映射环形缓冲区到用户空间
    size_t ring_size = req.tp_block_size * req.tp_block_nr;
    void *ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sock, 0);
    if (ring == MAP_FAILED) {
        perror("mmap");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 绑定到指定接口，并获取网口IP
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    socklen_t sll_len = sizeof(sll);
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(iface);
    if (sll.sll_ifindex == 0){
        perror("if_nametoindex\n");
        close(sock);
        return -1;
    }
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) == -1){
        perror("bind\n");
        close(sock);
        return -1;
    }
    uint32_t local_ip;
    if (get_interface_ip(iface, &local_ip) == -1) {
        printf("No Interface IP.\n");
        return -1;
    }

    int block_idx = 0;
    uint64_t total_packets = 0;

    int cursor = 0;
    double base_timestamp = 0;
    Packet_Window win = {0}; //保证窗口中没有垃圾值

    // 读取缓冲区
    while (1) {
        struct tpacket_block_desc *block = (struct tpacket_block_desc *)((uint8_t *)ring + (block_idx * req.tp_block_size));

        if ((block->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            // 使用 poll 避免忙等待
            struct pollfd pfd = {.fd = sock, .events = POLLIN};
            if (poll(&pfd, 1, POLL_TIMEOUT_MS) <= 0) {
                continue; // 超时或错误，继续轮询
            }
            // poll 返回后再次检查状态
            if ((block->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
                continue;
            }
        }
        
        uint8_t *frame = (uint8_t *)block + block->hdr.bh1.offset_to_first_pkt;
        double timestamp = 0;
        for(uint32_t i = 0; i< block->hdr.bh1.num_pkts; i++){
            struct tpacket3_hdr *tp3_hdr = (struct tpacket3_hdr *)frame;
            timestamp = (double)tp3_hdr->tp_sec + (double)tp3_hdr->tp_nsec / 1000000000.0;
            
            uint8_t *packet_loc = (uint8_t *)tp3_hdr + tp3_hdr->tp_mac;

            // 维护时间窗口并解析流量
            if(base_timestamp == 0){
                base_timestamp = timestamp;
                init_window_stat(&win);
            }else if (timestamp - base_timestamp > win_len){
                double features[FEATURES_NUM] = {0};
                compute_feature(&win, features, win_len);// 计算当前窗口内特征
                int label_index = predict(features);//推理获得预测标签
                char *label_map[] = LABELS;
                printf("Window %d:\n",cursor);
                printf("%.7f---%.7f:Total %d Packets\n",base_timestamp,timestamp,win.p_count);
                printf("Predicted Label:%s\n-----------------------\n", label_map[label_index]);
                init_window_stat(&win);// 初始化窗口状态，更新基准时间戳
                base_timestamp = timestamp;
                cursor++;
            };
            analyze_and_update_win(&win, packet_loc, &local_ip, max_packets);
            frame = (uint8_t *)tp3_hdr + tp3_hdr->tp_next_offset;
        } 

        // 释放 Block 给内核
        block->hdr.bh1.block_status = TP_STATUS_KERNEL;
        block_idx = (block_idx + 1) % req.tp_block_nr;
    }

    munmap(ring, ring_size);
    close(sock);
    return 0;
}

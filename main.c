#include "stdio.h"
#include "pcap.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"

#define BUFSIZE 1024

// char *iface_sender, *iface_reciver;
pcap_t *sender, *receiver;	// libpcap的接收网卡和发送网卡

int count = 0;

// libpcap接收数据包的回调函数
void pcap_callback(unsigned char *arg, const struct pcap_pkthdr *packet_header, unsigned char *packet_content){

	printf("第 %d 个数据包 : ts = %u; len = %u\n", ++count, packet_header->ts.tv_usec, packet_header->len);
	pcap_sendpacket(sender, packet_content, packet_header->len);
}

void phrase_arg(int argc, char **argv){

}

void signal_handler(){
	printf("[INFO] 停止捕获数据包");
	pcap_breakloop(receiver);	// 结束数据包捕获
}

int main(int argc, char **argv){

	// 捕获程序关闭信号
	signal(SIGINT, signal_handler); // 捕获 CTRL + C 信号

	char error_context[1024];   // 错误信息
      
	const char *iface_sender = "enp0s31f6";
	const char *iface_reciver = "enx000ec6d93790";
	
    //获取网卡
    sender = pcap_open_live(iface_sender, BUFSIZE, 1, 0, error_context);
	if(sender == NULL){
		printf("[ERROR] %s\n", error_context);
		exit(1);
	}

	receiver = pcap_open_live(iface_reciver, BUFSIZ, 1, 0, error_context);
	if(receiver == NULL){
		printf("[ERROR] %s\n", error_context);
		exit(1);
	}

	printf("接收网卡 (%s) 和发送网卡 (%s) 初始化完成，开始进行抓包\n", iface_reciver, iface_sender);

    // 调用回调函数
	if(pcap_loop(receiver, -1, pcap_callback, NULL) < 0){  
        perror("pcap_loop");
    }

    // 关闭并退出
    pcap_close(sender);
	pcap_close(receiver);
    return 0;
}

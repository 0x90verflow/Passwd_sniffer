#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <netinet/if_ether.h> // Ethernet header
#include <netinet/ip.h>

// Global pointer to interface list for cleanup
pcap_if_t *interfaces = NULL;
pcap_t *handle = NULL;

// Function to handle `SIGINT`
void exit_capture(int sig) {
    printf("\nFin de la capture...\n");
    if (interfaces != NULL) {
        pcap_freealldevs(interfaces);
    }
    if (handle != NULL){
    pcap_close(handle);
    }
    exit(0);
}

// Function to list available network interfaces
void available_interfaces() {
    int i = 1; // Interface index
    pcap_if_t *interface;

    printf("Interfaces réseau disponibles :\n");
    for (interface = interfaces; interface != NULL; interface = interface->next) {
        printf("%d. %s - %s\n",
               i++,
               interface->name,
               interface->description ? interface->description : "Pas de description");
    }
}

// Function to choose a network interface
char *choose_interface() {
    int interface_chosen, i = 1;
    pcap_if_t *interface;

    printf("Choisissez une interface (numéro) : ");
    if (scanf("%d", &interface_chosen) != 1) {
        fprintf(stderr, "Erreur : Entrée invalide.\n");
        exit_capture(0);
    }

    for (interface = interfaces; interface != NULL; interface = interface->next, i++) {
        if (i == interface_chosen) {
            printf("Vous avez choisi l'interface : %s\n", interface->name);
            return interface->name;
        }
    }

    fprintf(stderr, "Erreur : Interface invalide.\n");
    exit_capture(0);
}



void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    printf("\n==== Nouveau paquet capturé ====\n");
    printf("Longueur du paquet : %d octets\n", header->len);

    // Print source and destination MAC addresses
    printf("Adresse MAC source : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0],
           eth_header->ether_shost[1],
           eth_header->ether_shost[2],
           eth_header->ether_shost[3],
           eth_header->ether_shost[4],
           eth_header->ether_shost[5]);

    printf("Adresse MAC destination : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0],
           eth_header->ether_dhost[1],
           eth_header->ether_dhost[2],
           eth_header->ether_dhost[3],
           eth_header->ether_dhost[4],
           eth_header->ether_dhost[5]);

    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        printf("Protocole : IP\n");
        printf("Adresse IP source : %s\n", inet_ntoa(ip_header->ip_src));
        printf("Adresse IP destination : %s\n", inet_ntoa(ip_header->ip_dst));
    } else {
        printf("Paquet non IP capturé.\n");
    }
}

    // Check if there is content in http


int main() {
    char errorbuffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&interfaces, errorbuffer) == -1) {
        fprintf(stderr, "Erreur : %s\n", errorbuffer);
        return 1;
    }

    // Display interfaces
    available_interfaces();
    char *device = choose_interface();
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errorbuffer);
    if (handle == NULL) {
        fprintf(stderr, "Erreur : Impossible d'ouvrir l'interface %s - %s\n", device, errorbuffer);
        exit_capture(0);
    }
    printf("Capture en cours sur l'interface %s...\n", device);

    pcap_loop(handle, 0, packet_handler, NULL);


    // Handle SIGINT
    signal(SIGINT, exit_capture);

    printf("Appuyez sur Ctrl+C pour arrêter...\n");
    while (1) {
    sleep(1);
    }

    // unreachable but good practice
    if (interfaces != NULL) {
        pcap_freealldevs(interfaces);
    }

    return 0;
}

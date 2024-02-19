#include "debug.h"

void PrintBuffer(const char* buffer, int length, int headerLen) {

    // Calculate packet size from header
    // uint32_t packetSize = 0;
    // packetSize |= static_cast<uint32_t>(buffer[1]) << 24;
    // packetSize |= static_cast<uint32_t>(buffer[2]) << 16;
    // packetSize |= static_cast<uint32_t>(buffer[3]) << 8;
    // packetSize |= static_cast<uint32_t>(buffer[4]);
    // printf("Packet size: %d\n", packetSize);

    for (int i = 0; i < length; i++) {
    	if (i < headerLen) {
    		printf("\u001b[38;5;212m");
    	} else if (i >= length - 16) {
    		printf("\u001b[38;5;80m");
    	} else {
        	printf("\u001b[38;5;118m");
        }

        // Drukuj każdy bajt jako liczbę szesnastkową.
        printf("0x%02x ", (unsigned char)buffer[i]);

        // Przejście do nowej linii co 8 bajtów.
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\u001b[0m\n");
}
#include "contiki.h"
#include "services/shell/shell.h"
#include "services/shell/shell-commands.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define NETWORK_SIZE 10
static uint16_t networks[NETWORK_SIZE];

/*---------------------------------------------------------------------------*/

// Global attack veriables.
int sniff = 0;
int rank_attack = 0;
int blackhole_attack = 0;
int selective_forwarding = 0;
int version_attack = 0;
int dis_flood = 0;

/*---------------------------------------------------------------------------*/

void record_network(uint16_t pan_id) {
    for (int i = 0; i < NETWORK_SIZE; i++) {
        if (networks[i] == pan_id) {
            return;
        } else if (networks[i] == 0) {
            printf("\nDiscovered new network: %x\n", pan_id);

            networks[i] = pan_id;
            return;
        }
    }
}

void read_link_address(linkaddr_t *lladdr) {
    for(int i = 0; i < LINKADDR_SIZE; i++) {
        if(i > 0 && i % 2 == 0) {
            printf(".");
        }
        printf("%02x", lladdr->u8[i]);
    }
}

void read_frame(frame802154_t frame) {
    printf("\n[FROM: 0x%x ", frame.src_pid);
    read_link_address((linkaddr_t *)&frame.src_addr);

    printf("] [TO: 0x%x ", frame.dest_pid);
    read_link_address((linkaddr_t *)&frame.dest_addr);

    // printf("%u", frame.fcf.frame_type);

    printf("] [APPLICATION: ");
    for (int i = 0; i < frame.payload_len; i++) {
        char next_byte = frame.payload[i];
        if (isprint(next_byte)) {
            printf("%c", next_byte);
        }
    }
    printf("]\n");
}

void incoming_frame(frame802154_t frame) {
    record_network(frame.dest_pid);

    if (sniff) read_frame(frame);
}

/*---------------------------------------------------------------------------*/

//// NEW SHELL COMMANDS ////
static PT_THREAD(cmd_change_network(struct pt *pt, shell_output_func output, char *args))
{
    PT_BEGIN(pt);
    char *next_args;
    SHELL_ARGS_INIT(args, next_args);

    SHELL_ARGS_NEXT(args, next_args);
    if(args == NULL) {
        SHELL_OUTPUT(output, "You must enter a PAN ID!\n");
        PT_EXIT(pt);
    } else {
        uint16_t pan_id = (uint16_t) strtoul(args, NULL, 16);
        frame802154_set_pan_id(pan_id);
        SHELL_OUTPUT(output, "PAN ID Changed: %s\n", args);

        rpl_icmp6_dis_output(NULL);
        SHELL_OUTPUT(output, "DIS Sent\n");
    }

    PT_END(pt);
}

static PT_THREAD(cmd_networks(struct pt *pt, shell_output_func output, char *args))
{
    PT_BEGIN(pt);

    SHELL_OUTPUT(output, "Current PAN ID: 0x%x\n\n", frame802154_get_pan_id());
    SHELL_OUTPUT(output, "Available Networks: ");
    for (int i = 0; i < NETWORK_SIZE; i++) {
        if (networks[i] != 0) {
            SHELL_OUTPUT(output, "0x%x ", networks[i]);
        }
    }
    SHELL_OUTPUT(output, "\n");

    PT_END(pt);
}

static PT_THREAD(cmd_sniff(struct pt *pt, shell_output_func output, char *args))
{
    PT_BEGIN(pt);

    if (sniff) {
        sniff = 0;
        NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, 0);

        SHELL_OUTPUT(output, "Sniffing disabled\n");
    } else {
        sniff = 1;
        NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, 2);

        SHELL_OUTPUT(output, "Sniffing enabled\n");
    }

    PT_END(pt);
}

struct Attack {
    char *name;
    int *variable;
    char *description;
};

struct Attack attacks[] = {
    {"rank", &rank_attack, "Rank Decrease Attack"},
    {"blackhole", &blackhole_attack, "Blackhole Attack"},
    {"s-forward", &selective_forwarding, "Selective Forwarding"},
    {"version", &version_attack, "Version Increase Attack"},
    {"dis-flood", &dis_flood, "DIS Flooding"}
};

int ATTACK_COUNT = sizeof(attacks) / sizeof(*attacks);

void print_attack_codes(shell_output_func output) {
    SHELL_OUTPUT(output, "\nAttack Codes\n------------\n");
    for (int i = 0; i < ATTACK_COUNT; i++) {
        SHELL_OUTPUT(output, "%-10s\t", attacks[i].name);
        SHELL_OUTPUT(output, "%s\n", attacks[i].description);
    }
}

void print_attack_commands(shell_output_func output) {
    SHELL_OUTPUT(output, "\nAttack Commands\n---------------\n");
    SHELL_OUTPUT(output, "attack list\t\t\tShows whether attacks are enabled or disabled.\n");
    SHELL_OUTPUT(output, "attack enable [attack code]\tEnable an attack.\n");
    SHELL_OUTPUT(output, "attack disable [attack code]\tDisable an attack.\n");

    print_attack_codes(output);
}

void toggle_attack(shell_output_func output, char* attack, int toggle) {
    for (int i = 0; i < ATTACK_COUNT; i++) {
        if (strcmp(attack, attacks[i].name) == 0) {
            *attacks[i].variable = toggle;

            SHELL_OUTPUT(output, "%s ", attacks[i].description);
            if (toggle) { SHELL_OUTPUT(output, "enabled!\n"); }
            else { SHELL_OUTPUT(output, "disabled!\n"); }

            return;
        }
    }

    SHELL_OUTPUT(output, "Attack code doesn't exist!\n");
    print_attack_codes(output);
}

void list_attacks(shell_output_func output) {
    SHELL_OUTPUT(output, "\nAttacks\n-------\n");
    
    for (int i = 0; i < ATTACK_COUNT; i++) {
        SHELL_OUTPUT(output, "%-20s\t", attacks[i].description);
        if (*attacks[i].variable) {
            SHELL_OUTPUT(output, "[ENABLED]");
        } else {
            SHELL_OUTPUT(output, "[DISABLED]");
        }
        SHELL_OUTPUT(output, "\n");
    }
}

static PT_THREAD(cmd_attack(struct pt *pt, shell_output_func output, char *args))
{
    char *next_args;

    PT_BEGIN(pt);

    SHELL_ARGS_INIT(args, next_args);

    SHELL_ARGS_NEXT(args, next_args);
    char *action = args;

    SHELL_ARGS_NEXT(args, next_args);
    char *attack = args;

    if (action == NULL) print_attack_commands(output);
    else if (strcmp(action, "list") == 0) list_attacks(output);
    else if (strcmp(action, "enable") == 0) toggle_attack(output, attack, 1);
    else if (strcmp(action, "disable") == 0) toggle_attack(output, attack, 0);

    SHELL_ARGS_NEXT(args, next_args);

    PT_END(pt);
}

/*---------------------------------------------------------------------------*/

struct shell_command_t commands[] = {
    {"change-network", cmd_change_network, "Change PAN ID."},
    {"networks", cmd_networks, "Shows the node's current PAN ID and all available networks"},
    {"sniff", cmd_sniff, "Toggle sniffing mode on and off."},
    {"attack", cmd_attack, "Control attacks."}
};

struct shell_command_set_t command_set = {
    .next = NULL,
    .commands = commands,
};

/*---------------------------------------------------------------------------*/
PROCESS(attacker_process, "Attacker");
AUTOSTART_PROCESSES(&attacker_process);
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(attacker_process, ev, data)
{
    PROCESS_BEGIN();

    shell_command_set_register(&command_set);

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
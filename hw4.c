#include "sdb.h"

void print_usage(char *filename) {
    fprintf(stdout, "usage: %s [-s script] [program]\n", filename);
}

int main(int argc, char *argv[]) {
    int opt; bool error = false; FILE *fp = NULL;

    while ((opt = getopt(argc, argv, "s:")) != -1) {
        switch (opt) {
            case 's': fp = fopen(optarg, "r");  break;
            default : error = true;             break;
        }
    }

    if (error) {
        print_usage(argv[0]); exit(-1);
    }

    sdb_t *sdb = sdb_create(); fp = (fp == NULL)? stdin: fp;

    if (optind < argc) {
        sdb_load(sdb, argv[optind]);
    }

    setvbuf(fp, NULL, _IONBF, 0); setvbuf(stdout, NULL, _IONBF, 0);

    char buffer[BUFFER_SIZE], command[COMMAND_SIZE]; 
    memset(buffer, 0, sizeof(buffer)); memset(command, 0, sizeof(command));

    if (fp == stdin) {
        fputs("sdb> ", stdout);
    }

    while (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
        memset(command, 0, sizeof(command)); sscanf(buffer, "%s", command);
        
        if (!strcmp(command, "break") || !strcmp(command, "b")) {
            char address[ADDRESS_SIZE]; memset(address, 0, sizeof(address));
            sscanf(buffer, "%s %s", command, address); sdb_break(sdb, address);
        } else if (!strcmp(command, "cont") || !strcmp(command, "c")) {
            sdb_continue(sdb);
        } else if (!strcmp(command, "delete")) {
            char index[INDEX_SIZE]; memset(index, 0, sizeof(index));
            sscanf(buffer, "%s %s", command, index); sdb_delete(sdb, index);
        } else if (!strcmp(command, "disasm") || !strcmp(command, "d")) {
            char address[ADDRESS_SIZE]; memset(address, 0, sizeof(address));
            sscanf(buffer, "%s %s", command, address); sdb_disasm(sdb, address);
        } else if (!strcmp(command, "dump") || !strcmp(command, "x")) {
            char address[ADDRESS_SIZE]; memset(address, 0, sizeof(address));
            sscanf(buffer, "%s %s", command, address); sdb_dump(sdb, address);
        } else if (!strcmp(command, "exit") || !strcmp(command, "q")) {
            break;
        } else if (!strcmp(command, "get") || !strcmp(command, "g")) {
            char register_name[REGISTER_SIZE]; memset(register_name, 0, sizeof(register_name));
            sscanf(buffer, "%s %s", command, register_name); sdb_get(sdb, register_name);
        } else if (!strcmp(command, "getregs")) {
            sdb_getregs(sdb);
        } else if (!strcmp(command, "help") || !strcmp(command, "h")) {
            sdb_help();
        } else if (!strcmp(command, "list") || !strcmp(command, "l")) {
            sdb_list(sdb);
        } else if (!strcmp(command, "load")) {
            char filename[PATH_MAX]; memset(filename, 0, sizeof(filename));
            sscanf(buffer, "%s %s", command, filename); sdb_load(sdb, filename);
        } else if (!strcmp(command, "run") || !strcmp(command, "r")) {
            sdb_run(sdb);
        } else if (!strcmp(command, "vmmap") || !strcmp(command, "m")) {
            sdb_vmmap(sdb);
        } else if (!strcmp(command, "set") || !strcmp(command, "s")) {
            char register_name[REGISTER_SIZE], values[VALUE_SIZE];
            memset(register_name, 0, sizeof(register_name)); memset(values, 0, sizeof(values));
            sscanf(buffer, "%s %s %s", command, register_name, values);
            unsigned long long value = strtoll(values, NULL, 0); sdb_set(sdb, register_name, value);
        } else if (!strcmp(command, "si")) {
            sdb_step(sdb);
        } else if (!strcmp(command, "start")) {
            sdb_start(sdb);
        }

        if (fp == stdin) {
            fputs("sdb> ", stdout);
        }
    }


    return 0;
}

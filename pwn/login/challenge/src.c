#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define NAME_LEN 0x24
#define BIO_LEN 0x30
#define USER_COUNT 0x10

#define ADMIN_UID 0
#define USER_UID 1

typedef struct user {
    unsigned int uid;
    char name[NAME_LEN];
    char bio[BIO_LEN];
} user_t;

unsigned int curr_uid = 1000;
user_t admin;
user_t* users[USER_COUNT];
unsigned int current_user;



int getint(const char* msg) {
    printf(msg);
    char buf[0x8] = {};
    int choice = -1;
    read(0, buf, sizeof(buf));
    return atoi(buf);
    
}

int menu() {
    printf("1) Create user\n");
    printf("2) Select user\n");
    printf("3) Print users\n");
    printf("4) Delete user\n");
    printf("4) Login\n");
    printf("5) Exit\n");
    return getint("> ");

}

int create() {
    int idx = -1;
    int ret = -1;
    
    char namebuf[NAME_LEN] = {};
    printf("Enter user index.\n");
    idx = getint("> ");
    if (idx < 0 || idx >= USER_COUNT) {
        printf("Invalid user index!\n");
        return -1;
    }

    users[idx] = calloc(1, sizeof(user_t));
    users[idx]->uid = curr_uid++;

    printf("Enter user name.\n> ");
    ret = read(0, users[idx]->name, NAME_LEN - 1);
    if (ret < 0) {
        printf("Failed to read user name!\n");
        free(users[idx]);
        users[idx] = NULL;
        return -1;
    }
    users[idx]->name[ret-1] = '\0';

    ret = snprintf(users[idx]->bio, BIO_LEN - 1, "%s is a really cool hacker\n", users[idx]->name);
    if (ret < 0) {
        printf("Failed to create user bio\n");
        free(users[idx]);
        users[idx] = NULL;
        return -1;
    }
    users[idx]->bio[ret-1] = '\0';

    return 0;
}

int select_user() {
    int idx = -1;
    printf("Enter user index.\n");
    idx = getint("> ");
    if (idx < 0 || idx >= USER_COUNT || !users[idx]) {
        printf("Invalid user index!\n");
        return -1;
    }

    current_user = idx;
    return 0;
}

int delete_user() {
    int idx = -1;
    printf("Enter user index.\n");
    idx = getint("> ");
    if (idx < 0 || idx >= USER_COUNT || !users[idx]) {
        printf("Invalid user index!\n");
        return -1;
    }

    free(users[idx]);
    users[idx] = NULL;
    return 0;
}

void print_users() {
    for (int i = 0; i < USER_COUNT; i++) {
        if (!users[i]) continue;

        printf("User %d\n", i);
        printf("UID : %u\n", users[i]->uid);
        printf("Name: %s\n", users[i]->name);
        printf("Bio : %s\n\n", users[i]->bio);
    }
}

int login() {
    if (users[current_user] && users[current_user]->uid == ADMIN_UID) {
        int fd = open("flag.txt", O_RDONLY);
        char buf[0x100] = {};
        if (fd < 0) {
            printf("Flag file does not exist.. if this is on remote, contact an admin.\n");
            return -1;
        }

        read(fd, buf, 0x100);
        printf("Hi admin, here is your flag: %s\n", buf);
        return 0;
        
    } else {
        printf("You don't have permission to do that....\n");
        return -1;
    }
    
}

void setup() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

int main(void) {
    setup();
    admin.uid = 0;
    strcpy(admin.name, "admin");

    while (1) {
        int choice = menu();
        switch (choice) {
            case 1: 
                if (create() < 0) {
                    printf("Failed to create user!\n");
                }
                break;
             case 2: 
                if (select_user() < 0) {
                    printf("Failed to create user!\n");
                }
                break;
            
            case 3: 
                print_users();
                break;
                
            case 4: 
                if (delete_user() < 0) {
                    printf("Failed to delete user!\n");
                }
                break;
                
            case 5: 
                if (login() < 0) {
                    printf("Failed to login!\n");
                }
                break;
            case 6:
                return 0;
                break;

            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}

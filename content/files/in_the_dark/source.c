#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
const int MAX_X = 30;
const int MAX_Y = 10;
int p_x = 0;
int p_y = 7;
int g_x = 11;
int g_y = 7;
int g_dir = 1;
const int8_t MAP[10][30] = {
    {0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
    {0, 0, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
    {0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 1, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
    {1, 1, 0, 0, 0, 0, 2, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 9, 0, 0, 0, 0, 0, 0},
    {1, 1, 0, 1, 0, 0, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 0},
    {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2} 
};

int is_on_map(int next_y,int next_x){
    if(next_x < 0 || next_x >= MAX_X || next_y < 0 || next_y >= MAX_Y){
        return 0;
    }
    return 1;
}
void gravity(){
    while(MAP[p_y+1][p_x] == 0){
        p_y++;
    }
}
void move_right(){
    if(MAP[p_y][p_x+1] != 1 && is_on_map(p_y, p_x+1)){
        p_x++;
    }
}
void move_left(){
    if(MAP[p_y][p_x-1] != 1 && is_on_map(p_y, p_x-1)){
        p_x--;
    }
}
void jump_right(){
    if(MAP[p_y-1][p_x+1] != 1 && is_on_map(p_y-1, p_x+1)){
        p_x++;
        p_y--;
    }
    if(MAP[p_y-1][p_x+1] != 1 && is_on_map(p_y-1, p_x+1)){
        p_x++;
        p_y--;
    }
}
void jump_left(){
    if(MAP[p_y-1][p_x-1] != 1 && is_on_map(p_y-1, p_x-1)){
        p_x--;
        p_y--;
    }
    if(MAP[p_y-1][p_x-1] != 1 && is_on_map(p_y-1, p_x-1)){
        p_x--;
        p_y--;
    }
}
void goblin_move(){
    if(g_x == p_x && g_y == p_y){
        printf("Lost in the dark for eternity...\n");
        exit(0);
    }
    if(MAP[g_y+1][g_x+g_dir] != 1){
        g_dir *= -1;
    }
    if(MAP[g_y][g_x+g_dir] == 0 && is_on_map(g_y, g_x+g_dir)){
        g_x += g_dir;
    }
    if(g_x == p_x && g_y == p_y){
        printf("Lost in the dark for eternity...\n");
        exit(0);
    }
}
void touching_lava(){
    if(MAP[p_y+1][p_x] == 2 || MAP[p_y][p_x] == 2){
        printf("Lost in the dark for eternity...\n");
        exit(0);
    }
}
void on_flag(char *moves){
    if(MAP[p_y][p_x] == 9){
        printf("Thank you for helping poor mage, in return you can see what he found.\n");

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)moves, strlen(moves), hash);

        int s[] = {21, 1, 219, 168, 78, 186, 174, 230, 239, 179, 252, 33, 76, 212, 48, 31, 83, 250, 8, 155, 237, 254, 175, 24, 143, 92, 158, 171, 168, 68, 39, 217};
        printf("zeroday{");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%c", hash[i] ^ s[i]);
        }
        printf("}\n");
        exit(0);
    }
        
}
void decode_moves(char *moves){
    for(int i = 0; moves[i] != '\0'; i++){
        if(moves[i] == 'd'){
            move_right();
        }else if(moves[i] == 'a'){
            move_left();
        }else if(moves[i] == 'w'){
            if(moves[i+1] == 'd'){
                jump_right();
            }else if(moves[i+1] == 'a'){
                jump_left();
            }
            i++;
        }else{
            printf("He cant do it.\n");
            exit(0);
        }
        gravity();
        goblin_move();
        touching_lava();
        on_flag(moves);
    }
}
int main(){
    char moves[43] ={0};
    printf(" ██▓ ███▄    █    ▄▄▄█████▓ ██░ ██ ▓█████    ▓█████▄  ▄▄▄       ██▀███   ██ ▄█▀\n▓██▒ ██ ▀█   █    ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀    ▒██▀ ██▌▒████▄    ▓██ ▒ ██▒ ██▄█▒ \n▒██▒▓██  ▀█ ██▒   ▒ ▓██░ ▒░▒██▀▀██░▒███      ░██   █▌▒██  ▀█▄  ▓██ ░▄█ ▒▓███▄░ \n░██░▓██▒  ▐▌██▒   ░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄    ░▓█▄   ▌░██▄▄▄▄██ ▒██▀▀█▄  ▓██ █▄ \n░██░▒██░   ▓██░     ▒██▒ ░ ░▓█▒░██▓░▒████▒   ░▒████▓  ▓█   ▓██▒░██▓ ▒██▒▒██▒ █▄\n░▓  ░ ▒░   ▒ ▒      ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░    ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░▒ ▒▒ ▓▒\n ▒ ░░ ░░   ░ ▒░       ░     ▒ ░▒░ ░ ░ ░  ░    ░ ▒  ▒   ▒   ▒▒ ░  ░▒ ░ ▒░░ ░▒ ▒░\n ▒ ░   ░   ░ ░      ░       ░  ░░ ░   ░       ░ ░  ░   ░   ▒     ░░   ░ ░ ░░ ░ \n ░           ░              ░  ░  ░   ░  ░      ░          ░  ░   ░     ░  ░   \n                                              ░                                \n");
    printf("Fellow mage lost in the darkness, he needs your guidance to find the flag as fast as possible and survive... \n");
    scanf("%43s", moves);
    decode_moves(moves);
    printf("Lost in the dark for eternity...\n");
    exit(0);
}
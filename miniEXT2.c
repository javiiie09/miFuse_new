/*
 * Mini sistema de archivos tipo ext2 en C
 * Archivo contenedor: filesystem.bin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define BLOCK_SIZE 1024
#define MAX_INODES 128
#define MAX_BLOCKS 1024
#define INODES_PER_BLOCK (BLOCK_SIZE / sizeof(Inode))
#define FILENAME_MAX_LEN 28
#define ROOT_DIR_INODE 0
#define MAX_DIR_ENTRIES (BLOCK_SIZE / sizeof(DirEntry))

// Estructura del superbloque
typedef struct {
    uint32_t num_inodes;
    uint32_t num_blocks;
    uint32_t free_inodes;
    uint32_t free_blocks;
    uint32_t block_bitmap_offset;
    uint32_t inode_bitmap_offset;
    uint32_t inode_table_offset;
    uint32_t data_block_offset;
} Superblock;

// Estructura del inodo
typedef struct {
    uint8_t used;
    uint32_t size;
    uint32_t direct_blocks[12];
    uint8_t is_dir;
} Inode;

// Entrada de directorio
typedef struct {
    char name[FILENAME_MAX_LEN];
    uint32_t inode_index;
} DirEntry;

int fs_fd;
Superblock sb;
uint32_t current_dir_inode = 0;

void read_block(int block_num, void* buf) {
    lseek(fs_fd, block_num * BLOCK_SIZE, SEEK_SET);
    read(fs_fd, buf, BLOCK_SIZE);
}

void write_block(int block_num, void* buf) {
    lseek(fs_fd, block_num * BLOCK_SIZE, SEEK_SET);
    write(fs_fd, buf, BLOCK_SIZE);
}

void load_superblock() {
    lseek(fs_fd, 0, SEEK_SET);
    read(fs_fd, &sb, sizeof(Superblock));
}

void save_superblock() {
    lseek(fs_fd, 0, SEEK_SET);
    write(fs_fd, &sb, sizeof(Superblock));
}

int alloc_block() {
    uint8_t bitmap[BLOCK_SIZE];
    read_block(sb.block_bitmap_offset, bitmap);
    for (int i = sb.data_block_offset; i < MAX_BLOCKS; i++) {
        if (!(bitmap[i / 8] & (1 << (i % 8)))) {
            bitmap[i / 8] |= (1 << (i % 8));
            write_block(sb.block_bitmap_offset, bitmap);
            sb.free_blocks--;
            save_superblock();
            return i;
        }
    }
    return -1;
}

void free_block(int block_num) {
    uint8_t bitmap[BLOCK_SIZE];
    read_block(sb.block_bitmap_offset, bitmap);
    bitmap[block_num / 8] &= ~(1 << (block_num % 8));
    write_block(sb.block_bitmap_offset, bitmap);
    sb.free_blocks++;
    save_superblock();
}

int alloc_inode() {
    uint8_t bitmap[BLOCK_SIZE];
    read_block(sb.inode_bitmap_offset, bitmap);
    for (int i = 1; i < MAX_INODES; i++) {
        if (!(bitmap[i / 8] & (1 << (i % 8)))) {
            bitmap[i / 8] |= (1 << (i % 8));
            write_block(sb.inode_bitmap_offset, bitmap);
            sb.free_inodes--;
            save_superblock();
            return i;
        }
    }
    return -1;
}

void free_inode(int inode_index) {
    uint8_t bitmap[BLOCK_SIZE];
    read_block(sb.inode_bitmap_offset, bitmap);
    bitmap[inode_index / 8] &= ~(1 << (inode_index % 8));
    write_block(sb.inode_bitmap_offset, bitmap);
    sb.free_inodes++;
    save_superblock();
}

void read_inode(int index, Inode* inode) {
    int block = sb.inode_table_offset + index / INODES_PER_BLOCK;
    int offset = index % INODES_PER_BLOCK;
    Inode buffer[INODES_PER_BLOCK];
    read_block(block, buffer);
    *inode = buffer[offset];
}

void write_inode(int index, Inode* inode) {
    int block = sb.inode_table_offset + index / INODES_PER_BLOCK;
    int offset = index % INODES_PER_BLOCK;
    Inode buffer[INODES_PER_BLOCK];
    read_block(block, buffer);
    buffer[offset] = *inode;
    write_block(block, buffer);
}

int find_entry(int dir_inode_index, const char* name) {
    Inode dir_inode;
    read_inode(dir_inode_index, &dir_inode);
    if (!dir_inode.is_dir) return -1;

    DirEntry entries[MAX_DIR_ENTRIES];
    read_block(dir_inode.direct_blocks[0], entries);
    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (strcmp(entries[i].name, name) == 0) {
            return entries[i].inode_index;
        }
    }
    return -1;
}

void add_entry(int dir_inode_index, const char* name, int inode_index) {
    Inode dir_inode;
    read_inode(dir_inode_index, &dir_inode);
    DirEntry entries[MAX_DIR_ENTRIES];
    read_block(dir_inode.direct_blocks[0], entries);

    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (entries[i].inode_index == 0) {
            strncpy(entries[i].name, name, FILENAME_MAX_LEN);
            entries[i].inode_index = inode_index;
            write_block(dir_inode.direct_blocks[0], entries);
            break;
        }
    }
}

void remove_entry(int dir_inode_index, const char* name) {
    Inode dir_inode;
    read_inode(dir_inode_index, &dir_inode);
    DirEntry entries[MAX_DIR_ENTRIES];
    read_block(dir_inode.direct_blocks[0], entries);

    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (strcmp(entries[i].name, name) == 0) {
            entries[i].inode_index = 0;
            entries[i].name[0] = '\0';
            write_block(dir_inode.direct_blocks[0], entries);
            break;
        }
    }
}

void create_file(const char* name) {
    int inode_index = alloc_inode();
    if (inode_index < 0) return;

    Inode inode = {1, 0, {0}, 0};
    int block = alloc_block();
    if (block < 0) return;

    inode.direct_blocks[0] = block;
    write_inode(inode_index, &inode);
    add_entry(current_dir_inode, name, inode_index);
    printf("Archivo '%s' creado.\n", name);
}

void write_file(const char* name, const char* data) {
    int inode_index = find_entry(current_dir_inode, name);
    if (inode_index < 0) return;

    Inode inode;
    read_inode(inode_index, &inode);

    write_block(inode.direct_blocks[0], (void*)data);
    inode.size = strlen(data);
    write_inode(inode_index, &inode);
    printf("Datos escritos en '%s'.\n", name);
}

void read_file(const char* name) {
    int inode_index = find_entry(current_dir_inode, name);
    if (inode_index < 0) return;

    Inode inode;
    read_inode(inode_index, &inode);

    char buffer[BLOCK_SIZE + 1] = {0};
    read_block(inode.direct_blocks[0], buffer);
    printf("Contenido de '%s': %s\n", name, buffer);
}

void delete_file(const char* name) {
    int inode_index = find_entry(current_dir_inode, name);
    if (inode_index < 0) return;

    Inode inode;
    read_inode(inode_index, &inode);
    free_block(inode.direct_blocks[0]);
    free_inode(inode_index);
    remove_entry(current_dir_inode, name);
    printf("Archivo '%s' eliminado.\n", name);
}

void mkdir(const char* name) {
    int inode_index = alloc_inode();
    if (inode_index < 0) return;

    int block = alloc_block();
    if (block < 0) return;

    Inode dir = {1, 0, {block}, 1};
    write_inode(inode_index, &dir);

    DirEntry entries[MAX_DIR_ENTRIES] = {0};
    strcpy(entries[0].name, "."); entries[0].inode_index = inode_index;
    strcpy(entries[1].name, ".."); entries[1].inode_index = current_dir_inode;
    write_block(block, entries);

    add_entry(current_dir_inode, name, inode_index);
    printf("Directorio '%s' creado.\n", name);
}

void cd(const char* name) {
    int inode_index = find_entry(current_dir_inode, name);
    if (inode_index < 0) return;

    Inode inode;
    read_inode(inode_index, &inode);
    if (inode.is_dir) {
        current_dir_inode = inode_index;
        printf("Cambiado al directorio '%s'.\n", name);
    }
}

void ls() {
    Inode dir;
    read_inode(current_dir_inode, &dir);
    DirEntry entries[MAX_DIR_ENTRIES];
    read_block(dir.direct_blocks[0], entries);
    printf("Contenido del directorio:\n");
    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (entries[i].inode_index != 0) {
            printf(" - %s\n", entries[i].name);
        }
    }
}

void mkfs(const char* filename) {
    fs_fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, 0666);
    ftruncate(fs_fd, BLOCK_SIZE * MAX_BLOCKS);

    sb.num_inodes = MAX_INODES;
    sb.num_blocks = MAX_BLOCKS;
    sb.free_inodes = MAX_INODES - 1;
    sb.free_blocks = MAX_BLOCKS - 10;
    sb.block_bitmap_offset = 1;
    sb.inode_bitmap_offset = 2;
    sb.inode_table_offset = 3;
    sb.data_block_offset = 3 + (MAX_INODES / INODES_PER_BLOCK);

    save_superblock();

    uint8_t bitmap[BLOCK_SIZE] = {0};
    bitmap[0] |= 1;
    write_block(sb.block_bitmap_offset, bitmap);

    bitmap[0] |= 1;
    write_block(sb.inode_bitmap_offset, bitmap);

    Inode root = {1, 0, {sb.data_block_offset}, 1};
    lseek(fs_fd, sb.inode_table_offset * BLOCK_SIZE, SEEK_SET);
    write(fs_fd, &root, sizeof(Inode));

    DirEntry root_entries[MAX_DIR_ENTRIES] = {0};
    strcpy(root_entries[0].name, "."); root_entries[0].inode_index = 0;
    strcpy(root_entries[1].name, ".."); root_entries[1].inode_index = 0;
    write_block(sb.data_block_offset, root_entries);

    printf("Sistema de archivos creado exitosamente en %s\n", filename);
    close(fs_fd);
}

int main() {
    mkfs("filesystem.bin");
    fs_fd = open("filesystem.bin", O_RDWR);
    load_superblock();

    create_file("archivo1.txt");
    write_file("archivo1.txt", "Hola, mundo!");
    read_file("archivo1.txt");
    ls();

    mkdir("docs");
    cd("docs");
    create_file("readme.txt");
    write_file("readme.txt", "Este es un archivo en docs");
    read_file("readme.txt");
    ls();
    cd("..");

    delete_file("archivo1.txt");
    ls();

    close(fs_fd);
    return 0;
}
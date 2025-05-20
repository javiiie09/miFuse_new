#include "miniEXT2.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fuse.h>

#define FUSE_USE_VERSION 31
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <linux/ext2_fs.h>
#include <time.h>
#include <utime.h>

// Variables globales para la imagen y su tamaño
void *fs_map = NULL;
size_t fs_size = 0;

// Estructuras de ayuda para acceder a la imagen ext2
#define BASE ((unsigned char *)fs_map)
#define SUPERBLOCK ((struct ext2_super_block *)(BASE + 1024))
#define BLOCK_SIZE (1024 << SUPERBLOCK->s_log_block_size)
#define GROUP_DESC ((struct ext2_group_desc *)(BASE + 1024 + sizeof(struct ext2_super_block)))
#define INODE_TABLE (BASE + BLOCK_SIZE * GROUP_DESC->bg_inode_table)
#define INODE_SIZE (SUPERBLOCK->s_inode_size)
#define ROOT_INO 2

// Función para obtener un inodo por número
static struct ext2_inode *get_inode(int ino) {
    return (struct ext2_inode *)(INODE_TABLE + (ino - 1) * INODE_SIZE);
}

// Función para buscar un inodo por ruta absoluta
static int path_lookup(const char *path, struct ext2_inode **inode, int *ino_out) {
    if (strcmp(path, "/") == 0) {
        if (inode) *inode = get_inode(ROOT_INO);
        if (ino_out) *ino_out = ROOT_INO;
        return 0;
    }
    char *path_copy = strdup(path);
    if (!path_copy) return -ENOMEM;
    char *token, *saveptr;
    int ino = ROOT_INO;
    struct ext2_inode *cur = get_inode(ino);
    token = strtok_r(path_copy, "/", &saveptr);
    while (token && S_ISDIR(cur->i_mode)) {
        int found = 0;
        for (int blk = 0; blk < 12 && cur->i_block[blk]; ++blk) {
            unsigned char *block = BASE + BLOCK_SIZE * cur->i_block[blk];
            unsigned int offset = 0;
            while (offset < BLOCK_SIZE) {
                struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);
                if (entry->inode && strlen(token) == entry->name_len &&
                    strncmp(token, entry->name, entry->name_len) == 0) {
                    ino = entry->inode;
                    cur = get_inode(ino);
                    found = 1;
                    break;
                }
                offset += entry->rec_len;
            }
            if (found) break;
        }
        if (!found) {
            free(path_copy);
            return -ENOENT;
        }
        token = strtok_r(NULL, "/", &saveptr);
    }
    free(path_copy);
    if (inode) *inode = cur;
    if (ino_out) *ino_out = ino;
    return 0;
}

int miniEXT2_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    memset(stbuf, 0, sizeof(struct stat));
    struct ext2_inode *inode;
    int ino;
    int res = path_lookup(path, &inode, &ino);
    if (res < 0) return res;
    stbuf->st_ino = ino;
    stbuf->st_mode = inode->i_mode;
    stbuf->st_nlink = inode->i_links_count;
    stbuf->st_uid = inode->i_uid;
    stbuf->st_gid = inode->i_gid;
    stbuf->st_size = inode->i_size;
    stbuf->st_atime = inode->i_atime;
    stbuf->st_mtime = inode->i_mtime;
    stbuf->st_ctime = inode->i_ctime;
    return 0;
}

int miniEXT2_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    if (!S_ISDIR(inode->i_mode)) return -ENOTDIR;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    for (int blk = 0; blk < 12 && inode->i_block[blk]; ++blk) {
        unsigned char *block = BASE + BLOCK_SIZE * inode->i_block[blk];
        unsigned int off = 0;
        while (off < BLOCK_SIZE) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + off);
            if (entry->inode) {
                char name[EXT2_NAME_LEN+1];
                memcpy(name, entry->name, entry->name_len);
                name[entry->name_len] = 0;
                filler(buf, name, NULL, 0);
            }
            off += entry->rec_len;
        }
    }
    return 0;
}

int miniEXT2_open(const char *path, struct fuse_file_info *fi) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    if (!S_ISREG(inode->i_mode)) return -EISDIR;
    return 0;
}

int miniEXT2_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    if (!S_ISREG(inode->i_mode)) return -EISDIR;
    if (offset >= inode->i_size) return 0;
    if (offset + size > inode->i_size) size = inode->i_size - offset;
    size_t block_size = BLOCK_SIZE;
    size_t bytes_read = 0;
    size_t block_idx = offset / block_size;
    size_t block_off = offset % block_size;
    while (bytes_read < size && block_idx < 12 && inode->i_block[block_idx]) {
        unsigned char *block = BASE + block_size * inode->i_block[block_idx];
        size_t to_read = block_size - block_off;
        if (to_read > size - bytes_read) to_read = size - bytes_read;
        memcpy(buf + bytes_read, block + block_off, to_read);
        bytes_read += to_read;
        block_idx++;
        block_off = 0;
    }
    return bytes_read;
}

// Las siguientes funciones requieren escritura, que no es trivial en una imagen ext2 mapeada de solo lectura.
// Se implementan como solo lectura o retornan error.

// Implementaciones básicas de funciones de escritura para una imagen ext2 mapeada en memoria.
// Nota: Esto asume que la imagen fue mapeada con permisos de escritura (PROT_READ|PROT_WRITE)
// y que el usuario entiende los riesgos de modificar una imagen ext2 en bruto.

// Es necesario cambiar el mapeo en main() a PROT_READ|PROT_WRITE y MAP_SHARED para que funcione la escritura.

int miniEXT2_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    if (!S_ISREG(inode->i_mode)) return -EISDIR;
    if (offset > inode->i_size) return -EFBIG; // No soporta huecos
    size_t block_size = BLOCK_SIZE;
    size_t bytes_written = 0;
    size_t block_idx = offset / block_size;
    size_t block_off = offset % block_size;
    while (bytes_written < size && block_idx < 12 && inode->i_block[block_idx]) {
        unsigned char *block = BASE + block_size * inode->i_block[block_idx];
        size_t to_write = block_size - block_off;
        if (to_write > size - bytes_written) to_write = size - bytes_written;
        memcpy(block + block_off, buf + bytes_written, to_write);
        bytes_written += to_write;
        block_idx++;
        block_off = 0;
    }
    if (offset + bytes_written > inode->i_size)
        inode->i_size = offset + bytes_written;
    inode->i_mtime = inode->i_ctime = time(NULL);
    return bytes_written;
}

// Helpers para manipulación de bitmaps y asignación de inodos/bloques

static int alloc_inode() {
    unsigned char *inode_bitmap = BASE + BLOCK_SIZE * GROUP_DESC->bg_inode_bitmap;
    int ninodes = SUPERBLOCK->s_inodes_count;
    for (int i = 0; i < ninodes; ++i) {
        if (!(inode_bitmap[i / 8] & (1 << (i % 8)))) {
            inode_bitmap[i / 8] |= (1 << (i % 8));
            SUPERBLOCK->s_free_inodes_count--;
            GROUP_DESC->bg_free_inodes_count--;
            return i + 1;
        }
    }
    return -ENOSPC;
}

static int alloc_block() {
    unsigned char *block_bitmap = BASE + BLOCK_SIZE * GROUP_DESC->bg_block_bitmap;
    int nblocks = SUPERBLOCK->s_blocks_count;
    for (int i = 0; i < nblocks; ++i) {
        if (!(block_bitmap[i / 8] & (1 << (i % 8)))) {
            block_bitmap[i / 8] |= (1 << (i % 8));
            SUPERBLOCK->s_free_blocks_count--;
            GROUP_DESC->bg_free_blocks_count--;
            return i + 1;
        }
    }
    return -ENOSPC;
}

static int free_inode(int ino) {
    unsigned char *inode_bitmap = BASE + BLOCK_SIZE * GROUP_DESC->bg_inode_bitmap;
    int idx = ino - 1;
    if (inode_bitmap[idx / 8] & (1 << (idx % 8))) {
        inode_bitmap[idx / 8] &= ~(1 << (idx % 8));
        SUPERBLOCK->s_free_inodes_count++;
        GROUP_DESC->bg_free_inodes_count++;
        return 0;
    }
    return -EINVAL;
}

static int free_block(int blk) {
    unsigned char *block_bitmap = BASE + BLOCK_SIZE * GROUP_DESC->bg_block_bitmap;
    int idx = blk - 1;
    if (block_bitmap[idx / 8] & (1 << (idx % 8))) {
        block_bitmap[idx / 8] &= ~(1 << (idx % 8));
        SUPERBLOCK->s_free_blocks_count++;
        GROUP_DESC->bg_free_blocks_count++;
        return 0;
    }
    return -EINVAL;
}

// Helper para agregar/quitar entradas de directorio
static int add_dir_entry(struct ext2_inode *dir, int dir_ino, int new_ino, const char *name, uint8_t file_type) {
    size_t name_len = strlen(name);
    if (name_len > EXT2_NAME_LEN) return -ENAMETOOLONG;
    for (int blk = 0; blk < 12; ++blk) {
        if (!dir->i_block[blk]) {
            // Asignar nuevo bloque si es necesario
            int b = alloc_block();
            if (b < 0) return b;
            dir->i_block[blk] = b;
            dir->i_size += BLOCK_SIZE;
            unsigned char *block = BASE + BLOCK_SIZE * b;
            memset(block, 0, BLOCK_SIZE);
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)block;
            entry->inode = new_ino;
            entry->rec_len = BLOCK_SIZE;
            entry->name_len = name_len;
            entry->file_type = file_type;
            memcpy(entry->name, name, name_len);
            return 0;
        }
        unsigned char *block = BASE + BLOCK_SIZE * dir->i_block[blk];
        unsigned int off = 0;
        while (off < BLOCK_SIZE) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + off);
            unsigned int entry_len = 8 + entry->name_len + ((4 - (entry->name_len % 4)) % 4);
            if (entry->rec_len > entry_len) {
                // Hay espacio para una nueva entrada
                unsigned int free_len = entry->rec_len - entry_len;
                if (free_len >= 8 + name_len + ((4 - (name_len % 4)) % 4)) {
                    entry->rec_len = entry_len;
                    struct ext2_dir_entry *new_entry = (struct ext2_dir_entry *)(block + off + entry_len);
                    new_entry->inode = new_ino;
                    new_entry->rec_len = free_len;
                    new_entry->name_len = name_len;
                    new_entry->file_type = file_type;
                    memcpy(new_entry->name, name, name_len);
                    return 0;
                }
            }
            off += entry->rec_len;
        }
    }
    return -ENOSPC;
}

static int remove_dir_entry(struct ext2_inode *dir, int dir_ino, const char *name) {
    size_t name_len = strlen(name);
    for (int blk = 0; blk < 12 && dir->i_block[blk]; ++blk) {
        unsigned char *block = BASE + BLOCK_SIZE * dir->i_block[blk];
        unsigned int off = 0, prev_off = 0;
        struct ext2_dir_entry *prev = NULL;
        while (off < BLOCK_SIZE) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + off);
            if (entry->inode && entry->name_len == name_len &&
                strncmp(entry->name, name, name_len) == 0) {
                if (prev) {
                    prev->rec_len += entry->rec_len;
                } else {
                    // Primera entrada del bloque, solo poner inode a 0
                    entry->inode = 0;
                }
                return 0;
            }
            prev = entry;
            prev_off = off;
            off += entry->rec_len;
        }
    }
    return -ENOENT;
}

// Implementación mkdir
int miniEXT2_mkdir(const char *path, mode_t mode) {
    // Obtener padre y nombre
    char *path_copy = strdup(path);
    if (!path_copy) return -ENOMEM;
    char *base = strrchr(path_copy, '/');
    if (!base || base == path_copy) {
        free(path_copy);
        return -EINVAL;
    }
    *base = 0;
    const char *parent_path = path_copy;
    const char *name = base + 1;
    struct ext2_inode *parent;
    int parent_ino;
    int res = path_lookup(parent_path[0] ? parent_path : "/", &parent, &parent_ino);
    if (res < 0) { free(path_copy); return res; }
    if (!S_ISDIR(parent->i_mode)) { free(path_copy); return -ENOTDIR; }
    // Verificar que no exista
    struct ext2_inode *tmp;
    if (path_lookup(path, &tmp, NULL) == 0) { free(path_copy); return -EEXIST; }
    int ino = alloc_inode();
    if (ino < 0) { free(path_copy); return ino; }
    int blk = alloc_block();
    if (blk < 0) { free_inode(ino); free(path_copy); return blk; }
    struct ext2_inode *inode = get_inode(ino);
    memset(inode, 0, INODE_SIZE);
    inode->i_mode = (mode & 07777) | S_IFDIR;
    inode->i_uid = getuid();
    inode->i_gid = getgid();
    inode->i_links_count = 2; // . y ..
    inode->i_size = BLOCK_SIZE;
    inode->i_blocks = BLOCK_SIZE / 512;
    inode->i_block[0] = blk;
    inode->i_atime = inode->i_ctime = inode->i_mtime = time(NULL);
    // Crear . y .. en el nuevo directorio
    unsigned char *block = BASE + BLOCK_SIZE * blk;
    struct ext2_dir_entry *dot = (struct ext2_dir_entry *)block;
    dot->inode = ino;
    dot->rec_len = 12;
    dot->name_len = 1;
    dot->file_type = EXT2_FT_DIR;
    dot->name[0] = '.';
    struct ext2_dir_entry *dotdot = (struct ext2_dir_entry *)(block + 12);
    dotdot->inode = parent_ino;
    dotdot->rec_len = BLOCK_SIZE - 12;
    dotdot->name_len = 2;
    dotdot->file_type = EXT2_FT_DIR;
    dotdot->name[0] = '.';
    dotdot->name[1] = '.';
    // Agregar entrada al padre
    res = add_dir_entry(parent, parent_ino, ino, name, EXT2_FT_DIR);
    if (res < 0) {
        free_inode(ino);
        free_block(blk);
        free(path_copy);
        return res;
    }
    parent->i_links_count++;
    parent->i_mtime = parent->i_ctime = time(NULL);
    free(path_copy);
    return 0;
}

int miniEXT2_rmdir(const char *path) {
    // Buscar inodo y padre
    char *path_copy = strdup(path);
    if (!path_copy) return -ENOMEM;
    char *base = strrchr(path_copy, '/');
    if (!base || base == path_copy) {
        free(path_copy);
        return -EINVAL;
    }
    *base = 0;
    const char *parent_path = path_copy;
    const char *name = base + 1;
    struct ext2_inode *parent;
    int parent_ino;
    int res = path_lookup(parent_path[0] ? parent_path : "/", &parent, &parent_ino);
    if (res < 0) { free(path_copy); return res; }
    struct ext2_inode *inode;
    int ino;
    res = path_lookup(path, &inode, &ino);
    if (res < 0) { free(path_copy); return res; }
    if (!S_ISDIR(inode->i_mode)) { free(path_copy); return -ENOTDIR; }
    // Verificar que esté vacío (solo . y ..)
    int empty = 1;
    for (int blk = 0; blk < 12 && inode->i_block[blk]; ++blk) {
        unsigned char *block = BASE + BLOCK_SIZE * inode->i_block[blk];
        unsigned int off = 0;
        while (off < BLOCK_SIZE) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + off);
            if (entry->inode && !(entry->name_len == 1 && entry->name[0] == '.') &&
                !(entry->name_len == 2 && entry->name[0] == '.' && entry->name[1] == '.')) {
                empty = 0;
                break;
            }
            off += entry->rec_len;
        }
    }
    if (!empty) { free(path_copy); return -ENOTEMPTY; }
    // Quitar entrada del padre
    res = remove_dir_entry(parent, parent_ino, name);
    if (res < 0) { free(path_copy); return res; }
    parent->i_links_count--;
    parent->i_mtime = parent->i_ctime = time(NULL);
    // Liberar bloques e inodo
    for (int blk = 0; blk < 12 && inode->i_block[blk]; ++blk)
        free_block(inode->i_block[blk]);
    free_inode(ino);
    free(path_copy);
    return 0;
}

int miniEXT2_rename(const char *oldpath, const char *newpath) {
    // Solo soporta renombrar dentro del mismo directorio
    char *old_copy = strdup(oldpath);
    char *new_copy = strdup(newpath);
    if (!old_copy || !new_copy) { free(old_copy); free(new_copy); return -ENOMEM; }
    char *old_base = strrchr(old_copy, '/');
    char *new_base = strrchr(new_copy, '/');
    if (!old_base || !new_base) { free(old_copy); free(new_copy); return -EINVAL; }
    *old_base = 0; *new_base = 0;
    const char *old_parent_path = old_copy[0] ? old_copy : "/";
    const char *old_name = old_base + 1;
    const char *new_parent_path = new_copy[0] ? new_copy : "/";
    const char *new_name = new_base + 1;
    struct ext2_inode *old_parent, *new_parent;
    int old_parent_ino, new_parent_ino;
    int res = path_lookup(old_parent_path, &old_parent, &old_parent_ino);
    if (res < 0) { free(old_copy); free(new_copy); return res; }
    res = path_lookup(new_parent_path, &new_parent, &new_parent_ino);
    if (res < 0) { free(old_copy); free(new_copy); return res; }
    struct ext2_inode *inode;
    int ino;
    res = path_lookup(oldpath, &inode, &ino);
    if (res < 0) { free(old_copy); free(new_copy); return res; }
    // Quitar entrada vieja
    res = remove_dir_entry(old_parent, old_parent_ino, old_name);
    if (res < 0) { free(old_copy); free(new_copy); return res; }
    // Agregar entrada nueva
    uint8_t ftype = S_ISDIR(inode->i_mode) ? EXT2_FT_DIR : EXT2_FT_REG_FILE;
    res = add_dir_entry(new_parent, new_parent_ino, ino, new_name, ftype);
    if (res < 0) { free(old_copy); free(new_copy); return res; }
    free(old_copy); free(new_copy);
    return 0;
}

int miniEXT2_mknod(const char *path, mode_t mode, dev_t rdev) {
    // Obtener padre y nombre
    char *path_copy = strdup(path);
    if (!path_copy) return -ENOMEM;
    char *base = strrchr(path_copy, '/');
    if (!base || base == path_copy) {
        free(path_copy);
        return -EINVAL;
    }
    *base = 0;
    const char *parent_path = path_copy;
    const char *name = base + 1;
    struct ext2_inode *parent;
    int parent_ino;
    int res = path_lookup(parent_path[0] ? parent_path : "/", &parent, &parent_ino);
    if (res < 0) { free(path_copy); return res; }
    if (!S_ISDIR(parent->i_mode)) { free(path_copy); return -ENOTDIR; }
    // Verificar que no exista
    struct ext2_inode *tmp;
    if (path_lookup(path, &tmp, NULL) == 0) { free(path_copy); return -EEXIST; }
    int ino = alloc_inode();
    if (ino < 0) { free(path_copy); return ino; }
    struct ext2_inode *inode = get_inode(ino);
    memset(inode, 0, INODE_SIZE);
    inode->i_mode = mode;
    inode->i_uid = getuid();
    inode->i_gid = getgid();
    inode->i_links_count = 1;
    inode->i_size = 0;
    inode->i_blocks = 0;
    inode->i_atime = inode->i_ctime = inode->i_mtime = time(NULL);
    if (S_ISCHR(mode) || S_ISBLK(mode))
        inode->i_block[0] = rdev;
    // Agregar entrada al padre
    uint8_t ftype = S_ISDIR(mode) ? EXT2_FT_DIR : S_ISREG(mode) ? EXT2_FT_REG_FILE : S_ISCHR(mode) ? EXT2_FT_CHRDEV : S_ISBLK(mode) ? EXT2_FT_BLKDEV : EXT2_FT_UNKNOWN;
    res = add_dir_entry(parent, parent_ino, ino, name, ftype);
    if (res < 0) {
        free_inode(ino);
        free(path_copy);
        return res;
    }
    parent->i_mtime = parent->i_ctime = time(NULL);
    free(path_copy);
    return 0;
}

int miniEXT2_utimens(const char *path, const struct timespec tv[2]) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    inode->i_atime = tv[0].tv_sec;
    inode->i_mtime = tv[1].tv_sec;
    inode->i_ctime = time(NULL);
    return 0;
}

int miniEXT2_truncate(const char *path, off_t size) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    if (!S_ISREG(inode->i_mode)) return -EISDIR;
    if (size > inode->i_size) return -EFBIG; // No soporta crecer archivos
    inode->i_size = size;
    inode->i_mtime = inode->i_ctime = time(NULL);
    return 0;
}

int miniEXT2_unlink(const char *path) {
    // Obtener el inodo y su padre
    char *path_copy = strdup(path);
    if (!path_copy) return -ENOMEM;
    char *base = strrchr(path_copy, '/');
    if (!base || base == path_copy) {
        free(path_copy);
        return -EINVAL;
    }
    *base = 0;
    const char *parent_path = path_copy[0] ? path_copy : "/";
    const char *name = base + 1;
    struct ext2_inode *parent;
    int parent_ino;
    int res = path_lookup(parent_path, &parent, &parent_ino);
    if (res < 0) { free(path_copy); return res; }
    struct ext2_inode *inode;
    int ino;
    res = path_lookup(path, &inode, &ino);
    if (res < 0) { free(path_copy); return res; }
    if (S_ISDIR(inode->i_mode)) { free(path_copy); return -EISDIR; }
    // Quitar entrada del directorio padre
    res = remove_dir_entry(parent, parent_ino, name);
    if (res < 0) { free(path_copy); return res; }
    parent->i_mtime = parent->i_ctime = time(NULL);
    // Decrementar links y liberar si corresponde
    if (--inode->i_links_count == 0) {
        // Liberar bloques de datos
        for (int blk = 0; blk < 12 && inode->i_block[blk]; ++blk)
            free_block(inode->i_block[blk]);
        free_inode(ino);
    }
    inode->i_ctime = time(NULL);
    free(path_copy);
    return 0;
}

int miniEXT2_chmod(const char *path, mode_t mode) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    inode->i_mode = (inode->i_mode & ~07777) | (mode & 07777);
    inode->i_ctime = time(NULL);
    return 0;
}

int miniEXT2_chown(const char *path, uid_t uid, gid_t gid) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    if (uid != (uid_t)-1) inode->i_uid = uid;
    if (gid != (gid_t)-1) inode->i_gid = gid;
    inode->i_ctime = time(NULL);
    return 0;
}

int miniEXT2_utime(const char *path, struct utimbuf *ubuf) {
    struct ext2_inode *inode;
    int res = path_lookup(path, &inode, NULL);
    if (res < 0) return res;
    inode->i_atime = ubuf->actime;
    inode->i_mtime = ubuf->modtime;
    inode->i_ctime = time(NULL);
    return 0;
}

// Estructura de operaciones FUSE

static struct fuse_operations miniEXT2_oper = {
    .getattr = miniEXT2_getattr,
    .readdir = miniEXT2_readdir,
    .open = miniEXT2_open,
    .read = miniEXT2_read,
    .write = miniEXT2_write,
    .mkdir = miniEXT2_mkdir,
    .rmdir = miniEXT2_rmdir,
    .rename = miniEXT2_rename,
    .mknod = miniEXT2_mknod,
    .utimens = miniEXT2_utimens,
    .truncate = miniEXT2_truncate,
    .unlink = miniEXT2_unlink,
    .chmod = miniEXT2_chmod,
    .chown = miniEXT2_chown,
    .utime = miniEXT2_utime
};

int main(int argc, char *argv[]){
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <imagen>\n", argv[0]);
        return 1;
    }

    const char *imagen = argv[1];
    int fd = open(imagen, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    // Aquí puedes trabajar con la imagen mapeada en 'map'

    // Al final, liberar recursos:
    munmap(map, st.st_size);
    close(fd);
}
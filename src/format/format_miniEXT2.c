
#include "miniEXT2.h"

int main(int argc, char *argv[]){
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <imagen>\n", argv[0]);
        return 1;
    }

    FILE *img = fopen(argv[1], "wb+");
    if (!img) {
        perror("No se pudo abrir la imagen");
        return 1;
    }

    // Supongamos un tamaño fijo para la imagen y estructuras simples
    #define IMG_SIZE (1024 * 1024) // 1MB
    #define BLOCK_SIZE 1024
    #define INODE_TABLE_SIZE 128

    // Limpiar la imagen
    char zero = 0;
    for (size_t i = 0; i < IMG_SIZE; ++i)
        fwrite(&zero, 1, 1, img);

    // Inicializar superbloque (ejemplo simple)
    fseek(img, 0, SEEK_SET);
    struct {
        int magic;
        int block_size;
        int inode_table_size;
        int free_blocks;
        int free_inodes;
    } superblock = {0xEF53, BLOCK_SIZE, INODE_TABLE_SIZE, (IMG_SIZE/BLOCK_SIZE)-10, INODE_TABLE_SIZE-1};
    fwrite(&superblock, sizeof(superblock), 1, img);

    // Inicializar bitmap de bloques e inodos (marcando el bloque 0 y el inodo 0 como usados)
    unsigned char block_bitmap[IMG_SIZE/BLOCK_SIZE/8] = {0};
    block_bitmap[0] |= 0x01;
    fwrite(block_bitmap, sizeof(block_bitmap), 1, img);

    unsigned char inode_bitmap[INODE_TABLE_SIZE/8] = {0};
    inode_bitmap[0] |= 0x01;
    fwrite(inode_bitmap, sizeof(inode_bitmap), 1, img);

    // Inicializar tabla de inodos (solo raíz)
    struct {
        int mode;
        int size;
        int block;
    } inode = {040755, BLOCK_SIZE, 1};
    fwrite(&inode, sizeof(inode), 1, img);

    // Rellenar el resto de la tabla de inodos con ceros
    char inode_zero[sizeof(inode)] = {0};
    for (int i = 1; i < INODE_TABLE_SIZE; ++i)
        fwrite(inode_zero, sizeof(inode_zero), 1, img);

    fclose(img);
    printf("Imagen formateada e inicializada correctamente.\n");
}
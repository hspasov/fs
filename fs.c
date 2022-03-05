#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <regex.h>

#define DEBUG_ENABLED 0
#define DIRECT_BLOCKS_SIZE 13
#define BLOCK_SIZE 512
#define BITS_IN_BYTE 8
#define VALID_FILENAME_PATTERN "^[a-zA-Z0-9\\-_.]+$"


struct garbage_collection {
  void** ptrs_to_free;
  size_t ptrs_to_free_count;
  size_t ptrs_to_free_size;
  int* fds_to_close;
  size_t fds_to_close_count;
  size_t fds_to_close_size;
};


struct fs_meta {
  char root_dir_label;
  char dir_sep;
  size_t block_size;
  size_t superblock;
  size_t bitmap_info_blocks_start;
  size_t bitmap_info_blocks_count;
  size_t data_blocks_count;
  size_t fs_total_blocks_count;
  size_t data_blocks_start;
  size_t next_free_data_block;
  size_t root_dir_inode_data_block;
  int fd;
  char* fs_path;
  struct garbage_collection gbc;
  regex_t valid_file_name_pattern;
};


struct fs_inode {
  size_t size;
  char type;
  uid_t oid;
  gid_t gid;
  time_t mtime;
  mode_t perms;
  size_t hardlinks_count;
  size_t direct_blocks[DIRECT_BLOCKS_SIZE];
  size_t single_indirect_block;
  size_t double_indirect_block;
  size_t triple_indirect_block;
  size_t self_inode_data_block;
};


struct fs_str {
  char * bytes;
  size_t length;
};


void str_print (const struct fs_str * const str) {
  for (size_t i = 0; i < str->length; i++) {
    printf("%c", str->bytes[i]);
  }
}


void destroy_fs_meta (struct fs_meta* const fsm) {
  regfree(&fsm->valid_file_name_pattern);

  for (size_t i = 0; i < fsm->gbc.ptrs_to_free_count; i++) {
    free(fsm->gbc.ptrs_to_free[i]);
  }

  for (size_t i = 0; i < fsm->gbc.fds_to_close_count; i++) {
    close(fsm->gbc.fds_to_close[i]);
  }

  free(fsm->gbc.ptrs_to_free);
  free(fsm->gbc.fds_to_close);
  free(fsm);
}


void assert (struct fs_meta* const fsm, const int cond, const int exit_code) {
  if (DEBUG_ENABLED) {
    printf("TRACE %d\n", exit_code);
  }

  if (!cond) {
    printf("ERROR!\n");
    destroy_fs_meta(fsm);
    exit(exit_code);
  }
}


void assert_user (struct fs_meta* const fsm, const int cond, const int exit_code, const char* const err_msg) {
  if (!cond) {
    printf("%s\n", err_msg);
  }

  assert(fsm, cond, exit_code);
}


void assert_fsck (struct fs_meta* const fsm, const int cond, const int exit_code, const char* const info_msg) {
  if (cond) {
    printf("%s ... ", info_msg);
  }

  assert(fsm, cond, exit_code);

  printf("OK\n");
}


void free_before_exit (struct fs_meta* const fsm, void* const ptr) {
  if (fsm->gbc.ptrs_to_free_count == 0) {
    fsm->gbc.ptrs_to_free_count = 1;
    fsm->gbc.ptrs_to_free_size = 1;

    fsm->gbc.ptrs_to_free = malloc(fsm->gbc.ptrs_to_free_count * sizeof(void*));

    fsm->gbc.ptrs_to_free[0] = ptr;

    return;
  }

  if (fsm->gbc.ptrs_to_free_count >= fsm->gbc.ptrs_to_free_size) {
    fsm->gbc.ptrs_to_free_size *= 2;

    void** new_ptrs_to_free = realloc(fsm->gbc.ptrs_to_free, fsm->gbc.ptrs_to_free_size * sizeof(void*));

    assert(fsm, new_ptrs_to_free != NULL, 51);

    fsm->gbc.ptrs_to_free = new_ptrs_to_free;
  }

  fsm->gbc.ptrs_to_free[fsm->gbc.ptrs_to_free_count] = ptr;
  fsm->gbc.ptrs_to_free_count++;
}


void close_before_exit (struct fs_meta* const fsm, int const fd) {
  if (fsm->gbc.fds_to_close_count == 0) {
    fsm->gbc.fds_to_close_count = 1;
    fsm->gbc.fds_to_close_size = 1;

    fsm->gbc.fds_to_close = malloc(fsm->gbc.fds_to_close_count * sizeof(int));

    fsm->gbc.fds_to_close[0] = fd;

    return;
  }

  if (fsm->gbc.fds_to_close_count >= fsm->gbc.fds_to_close_size) {
    fsm->gbc.fds_to_close_size *= 2;

    int* new_fds_to_close = realloc(fsm->gbc.fds_to_close, fsm->gbc.fds_to_close_size * sizeof(int));

    assert(fsm, new_fds_to_close != NULL, 52);

    fsm->gbc.fds_to_close = new_fds_to_close;
  }

  fsm->gbc.fds_to_close[fsm->gbc.fds_to_close_count] = fd;
  fsm->gbc.fds_to_close_count++;
}


void* fs_malloc (struct fs_meta* const fsm, const size_t size) {
  void* const ptr = malloc(size);

  assert(fsm, ptr != NULL, 93);

  free_before_exit(fsm, ptr);

  return ptr;
}


int fs_open (struct fs_meta* const fsm, char* const path, int flags, int mode) {
  int fd = open(path, flags, mode);

  assert(fsm, fd != -1, 53);

  close_before_exit(fsm, fd);

  return fd;
}


void set_bit (struct fs_meta* const fsm, unsigned char* const byte, const size_t bit_offset, const unsigned char status) {
  const size_t bitshifts = BITS_IN_BYTE - bit_offset - 1;

  if (status == 0) {
    unsigned char mask = ~(1 << bitshifts);

    *byte &= mask;
  } else if (status == 1) {
    unsigned char mask = 1 << bitshifts;

    *byte |= mask;
  } else {
    assert(fsm, 0, 38);
  }
}


void set_block_status (struct fs_meta* const fsm, const size_t data_block, const unsigned char status) {
  assert_user(fsm, data_block < fsm->data_blocks_count, 39, "No space available!");

  const size_t bitmap_info_block = (data_block / BITS_IN_BYTE) / fsm->block_size;
  const size_t bitmap_block_byte_offset = (data_block / BITS_IN_BYTE) % fsm->block_size;
  const size_t data_block_bit_offset = data_block % BITS_IN_BYTE;

  const size_t offset = (fsm->bitmap_info_blocks_start + bitmap_info_block) * fsm->block_size;

  unsigned char* const bitmap_block_buffer = fs_malloc(fsm, fsm->block_size * sizeof(unsigned char));

  assert(fsm, lseek(fsm->fd, offset, SEEK_SET) == (off_t)offset, 40);
  assert(fsm, read(fsm->fd, bitmap_block_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 41);

  if (status == 1) {
    const size_t bitshifts = BITS_IN_BYTE - data_block_bit_offset - 1;

    assert(fsm, (bitmap_block_buffer[bitmap_block_byte_offset] >> bitshifts) % 2 == 0, 75);
  }

  set_bit(fsm, bitmap_block_buffer + bitmap_block_byte_offset, data_block_bit_offset, status);

  assert(fsm, lseek(fsm->fd, offset, SEEK_SET) == (off_t)offset, 42);
  assert(fsm, write(fsm->fd, bitmap_block_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 43);
}


size_t get_free_data_block (struct fs_meta* const fsm) {
  const size_t free_data_block = fsm->next_free_data_block;

  const unsigned char full_data_block_byte = ~0;

  unsigned char* const bitmap_block_buffer = fs_malloc(fsm, fsm->block_size * sizeof(unsigned char));

  size_t bitmap_info_blocks_checked = 0;
  size_t next_free_data_block = 0;

  while (1) {
    assert_user(fsm, next_free_data_block < fsm->data_blocks_count, 44, "No space available!");
    assert_user(fsm, bitmap_info_blocks_checked < fsm->bitmap_info_blocks_count, 45, "No space available!");

    const size_t bitmap_block_buffer_offset = (next_free_data_block / BITS_IN_BYTE) % fsm->block_size;

    if (bitmap_block_buffer_offset == 0) {
      const size_t offset = (fsm->bitmap_info_blocks_start + bitmap_info_blocks_checked) * fsm->block_size;

      assert(fsm, lseek(fsm->fd, offset, SEEK_SET) == (off_t)offset, 47);
      assert(fsm, read(fsm->fd, bitmap_block_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 46);

      bitmap_info_blocks_checked++;
    }

    int data_block_byte_pos = BITS_IN_BYTE - 1;
    unsigned char data_block_byte = bitmap_block_buffer[bitmap_block_buffer_offset];

    if (data_block_byte != full_data_block_byte) {
      int found_free_data_block = 0;

      while (data_block_byte_pos >= 0) {
        assert(fsm, !found_free_data_block, 48);

        if (data_block_byte % 2 == 0 && next_free_data_block + data_block_byte_pos != free_data_block) {
          found_free_data_block = 1;
          break;
        }

        data_block_byte >>= 1;
        data_block_byte_pos--;
      }

      if (found_free_data_block) {
        next_free_data_block += data_block_byte_pos;
        break;
      }
    }

    next_free_data_block += BITS_IN_BYTE;
  }

  fsm->next_free_data_block = next_free_data_block;

  return free_data_block;
}


void create_empty_inode (struct fs_meta * const fsm, struct fs_inode* const inode, const size_t data_block, const char type) {
  assert(fsm, type == 'd' || type == '-', 65);

  const size_t empty_content_block = get_free_data_block(fsm);
  set_block_status(fsm, empty_content_block, 1);

  inode->type = type;
  inode->size = 0;
  inode->oid = 0;
  inode->gid = 0;
  inode->perms = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
  inode->mtime = time(NULL);
  inode->hardlinks_count = 1;
  inode->direct_blocks[0] = empty_content_block;
  inode->single_indirect_block = 0;
  inode->double_indirect_block = 0;
  inode->triple_indirect_block = 0;
  inode->self_inode_data_block = data_block;

  for (size_t block = 1; block < DIRECT_BLOCKS_SIZE; block++) {
    inode->direct_blocks[block] = 0;
  }
}


struct fs_meta* get_fs_meta (char * const fs_path) {
  struct fs_meta* fsm = (struct fs_meta*) malloc(sizeof(struct fs_meta));

  if (fsm == NULL) {
    exit(14);
  }

  const int fd = open(fs_path, O_RDONLY);

  if (fd < 0) {
    printf("ERROR!\n");
    free(fsm);
    exit(27);
  }

  fsm->fd = fd;
  fsm->fs_path = fs_path;

  char* const data_block_buffer = malloc(BLOCK_SIZE * sizeof(char));

  if (data_block_buffer == NULL) {
    printf("ERROR!\n");
    close(fsm->fd);
    free(fsm);
    exit(29);
  }

  if (read(fsm->fd, data_block_buffer, BLOCK_SIZE) != BLOCK_SIZE) {
    printf("ERROR!\n");
    close(fsm->fd);
    free(fsm);
    free(data_block_buffer);
    exit(28);
  }

  size_t data_block_buffer_offset = 0;

  fsm->root_dir_label = *((char*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(char);

  fsm->dir_sep = *((char*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(char);

  fsm->block_size = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  fsm->superblock = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  fsm->bitmap_info_blocks_start = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  fsm->bitmap_info_blocks_count = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  fsm->data_blocks_count = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  fsm->fs_total_blocks_count = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  fsm->data_blocks_start = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  fsm->root_dir_inode_data_block = *((size_t*) (data_block_buffer + data_block_buffer_offset));

  if (regcomp(&fsm->valid_file_name_pattern, VALID_FILENAME_PATTERN, REG_EXTENDED | REG_NOSUB) != 0) {
    close(fsm->fd);
    free(fsm);
    free(data_block_buffer);
    exit(129);
  }

  fsm->gbc.ptrs_to_free_size = 0;
  fsm->gbc.ptrs_to_free_count = 0;
  fsm->gbc.ptrs_to_free = NULL;
  fsm->gbc.fds_to_close_size = 0;
  fsm->gbc.fds_to_close_count = 0;
  fsm->gbc.fds_to_close = NULL;

  free_before_exit(fsm, data_block_buffer);
  close_before_exit(fsm, fsm->fd);

  fsm->next_free_data_block = 0;
  get_free_data_block(fsm);

  return fsm;
}


void allow_write (struct fs_meta* const fsm) {
  fsm->fd = fs_open(fsm, fsm->fs_path, O_RDWR, 0);
}


void calc_free_block_bitmap_size (const size_t fs_total_blocks_count, size_t * const bitmap_info_blocks_count, size_t * const data_blocks_count) {
  *bitmap_info_blocks_count = (fs_total_blocks_count + 4095) / 4097; // formula explained in docs
  *data_blocks_count = fs_total_blocks_count - *bitmap_info_blocks_count - 1;
}


size_t calc_data_offset (const struct fs_meta* const fsm, const size_t data_block) {
  return (fsm->data_blocks_start + data_block) * fsm->block_size;
}


size_t read_block (struct fs_meta* const fsm, char* const file_content, const int level, const size_t data_block, const size_t blocks_to_read, const size_t blocks_read) {
  assert(fsm, level >= 0 && level <= 3, 59);
  assert(fsm, blocks_read < blocks_to_read, 64);

  size_t data_offset = calc_data_offset(fsm, data_block);

  assert(fsm, lseek(fsm->fd, data_offset, SEEK_SET) == (off_t)data_offset, 60);

  size_t current_blocks_read = 0;

  if (level == 0) {
    assert(fsm, read(fsm->fd, file_content + blocks_read * fsm->block_size, fsm->block_size) == (ssize_t)fsm->block_size, 58);

    current_blocks_read++;
  } else if (level >= 1 && level <= 3) {
    char* const data_block_addresses_buffer = fs_malloc(fsm, fsm->block_size * sizeof(char));

    assert(fsm, read(fsm->fd, (char*) data_block_addresses_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 63);

    const size_t data_block_addresses_to_read = fsm->block_size / sizeof(size_t);
    size_t data_block_addresses_read = 0;

    while (blocks_read + current_blocks_read < blocks_to_read && data_block_addresses_read < data_block_addresses_to_read) {
      const size_t next_data_block = *((size_t*) (data_block_addresses_buffer + data_block_addresses_read * sizeof(size_t)));

      current_blocks_read += read_block(fsm, file_content, level - 1, next_data_block, blocks_to_read, blocks_read + current_blocks_read);
      data_block_addresses_read++;
    }
  } else {
    assert(fsm, 0, 62);
  }

  return current_blocks_read;
}


void read_entire_file (struct fs_meta* const fsm, const struct fs_inode* const inode, const struct fs_str * const file_content) {
  const size_t blocks_to_read = inode->size / fsm->block_size + 1;
  size_t blocks_read = 0;

  while (blocks_read < blocks_to_read && blocks_read < DIRECT_BLOCKS_SIZE) {
    blocks_read += read_block(fsm, file_content->bytes, 0, inode->direct_blocks[blocks_read], blocks_to_read, blocks_read);
  }

  if (blocks_read < blocks_to_read) {
    blocks_read += read_block(fsm, file_content->bytes, 1, inode->single_indirect_block, blocks_to_read, blocks_read);
  }

  if (blocks_read < blocks_to_read) {
    blocks_read += read_block(fsm, file_content->bytes, 2, inode->double_indirect_block, blocks_to_read, blocks_read);
  }

  if (blocks_read < blocks_to_read) {
    blocks_read += read_block(fsm, file_content->bytes, 3, inode->triple_indirect_block, blocks_to_read, blocks_read);
  }
}


size_t free_data_block (struct fs_meta* const fsm, const size_t data_block, const int level, const size_t data_blocks_to_free, const size_t data_blocks_freed) {
  assert(fsm, level >= 0 && level <= 3, 66);

  size_t current_data_blocks_freed = 0;

  if (level == 0) {
    current_data_blocks_freed++;
  } else if (level >= 1 && level <= 3) {
    char* const data_block_buffer = fs_malloc(fsm, fsm->block_size);

    const size_t data_offset = calc_data_offset(fsm, data_block);

    assert(fsm, lseek(fsm->fd, data_offset, SEEK_SET) == (off_t)data_offset, 67);
    assert(fsm, read(fsm->fd, (char*) data_block_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 68);

    const size_t data_block_addresses_to_free = fsm->block_size / sizeof(size_t);
    size_t data_block_addresses_freed = 0;

    while (data_blocks_freed + current_data_blocks_freed < data_blocks_to_free && data_block_addresses_freed < data_block_addresses_to_free) {
      size_t next_data_block = *((size_t*) (data_block_buffer + data_block_addresses_freed * sizeof(size_t)));

      current_data_blocks_freed += free_data_block(fsm, next_data_block, level - 1, data_blocks_to_free, data_blocks_freed + current_data_blocks_freed);
      data_block_addresses_freed++;
    }
  } else {
    assert(fsm, 0, 69);
  }

  set_block_status(fsm, data_block, 0);

  return current_data_blocks_freed;
}


void inode_free_all_data_blocks (struct fs_meta* const fsm, struct fs_inode* const inode) {
  const size_t data_blocks_to_free = inode->size / fsm->block_size + 1;

  size_t data_blocks_freed = 0;

  while (data_blocks_freed < data_blocks_to_free && data_blocks_freed < DIRECT_BLOCKS_SIZE) {
    data_blocks_freed += free_data_block(fsm, inode->direct_blocks[data_blocks_freed], 0, data_blocks_to_free, data_blocks_freed);
  }

  if (data_blocks_freed < data_blocks_to_free) {
    data_blocks_freed += free_data_block(fsm, inode->single_indirect_block, 1, data_blocks_to_free, data_blocks_freed);
  }

  if (data_blocks_freed < data_blocks_to_free) {
    data_blocks_freed += free_data_block(fsm, inode->double_indirect_block, 2, data_blocks_to_free, data_blocks_freed);
  }

  if (data_blocks_freed < data_blocks_to_free) {
    data_blocks_freed += free_data_block(fsm, inode->triple_indirect_block, 3, data_blocks_to_free, data_blocks_freed);
  }

  assert(fsm, data_blocks_freed == data_blocks_to_free, 77);

  inode->size = 0;
}


size_t write_data_to_block (struct fs_meta* const fsm, size_t* const data_block, const int level, char* const file_content, const size_t blocks_to_write, const size_t blocks_written) {
  assert(fsm, level >= 0 && level <= 3, 79);

  *data_block = get_free_data_block(fsm);
  set_block_status(fsm, *data_block, 1);

  const size_t data_offset = calc_data_offset(fsm, *data_block);

  size_t current_blocks_written = 0;

  if (level == 0) {
    assert(fsm, lseek(fsm->fd, data_offset, SEEK_SET) == (off_t)data_offset, 80);
    assert(fsm, write(fsm->fd, file_content + blocks_written * fsm->block_size, fsm->block_size) == (ssize_t)fsm->block_size, 81);

    current_blocks_written++;
  } else if (level >= 1 && level <= 3) {
    const size_t data_block_addresses_to_write = fsm->block_size / sizeof(size_t);

    size_t* const data_block_addresses_buffer = fs_malloc(fsm, fsm->block_size);

    memset(data_block_addresses_buffer, 0, fsm->block_size);

    size_t data_block_addresses_written = 0;

    while (blocks_written + current_blocks_written < blocks_to_write && data_block_addresses_written < data_block_addresses_to_write) {
      size_t written_data_block;
      current_blocks_written += write_data_to_block(fsm, &written_data_block, level - 1, file_content, blocks_to_write, blocks_written + current_blocks_written);

      data_block_addresses_buffer[data_block_addresses_written] = written_data_block;

      data_block_addresses_written++;
    }

    assert(fsm, lseek(fsm->fd, data_offset, SEEK_SET) == (off_t)data_offset, 57);
    assert(fsm, write(fsm->fd, (char*) data_block_addresses_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 84);
  } else {
    assert(fsm, 0, 78);
  }

  return current_blocks_written;
}


void write_to_file (struct fs_meta* const fsm, struct fs_inode* const inode, const struct fs_str * const file_content) {
  inode_free_all_data_blocks(fsm, inode);

  const size_t data_blocks_to_write = file_content->length / fsm->block_size + 1;
  size_t data_blocks_written = 0;

  while (data_blocks_written < DIRECT_BLOCKS_SIZE && data_blocks_written < data_blocks_to_write) {
    data_blocks_written += write_data_to_block(fsm, inode->direct_blocks + data_blocks_written, 0, file_content->bytes, data_blocks_to_write, data_blocks_written);
  }

  if (data_blocks_written < data_blocks_to_write) {
    data_blocks_written += write_data_to_block(fsm, &inode->single_indirect_block, 1, file_content->bytes, data_blocks_to_write, data_blocks_written);
  }

  if (data_blocks_written < data_blocks_to_write) {
    data_blocks_written += write_data_to_block(fsm, &inode->double_indirect_block, 2, file_content->bytes, data_blocks_to_write, data_blocks_written);
  }

  if (data_blocks_written < data_blocks_to_write) {
    data_blocks_written += write_data_to_block(fsm, &inode->triple_indirect_block, 3, file_content->bytes, data_blocks_to_write, data_blocks_written);
  }

  assert(fsm, data_blocks_written == data_blocks_to_write, 76);

  inode->size = file_content->length;
  inode->mtime = time(NULL);
}


void read_inode (struct fs_meta* const fsm, const size_t data_block, struct fs_inode* const inode) {
  const size_t offset = calc_data_offset(fsm, data_block);

  inode->self_inode_data_block = data_block;

  assert(fsm, lseek(fsm->fd, offset, SEEK_SET) == (off_t)offset, 91);

  char* const data_block_buffer = fs_malloc(fsm, fsm->block_size * sizeof(char));

  assert(fsm, read(fsm->fd, data_block_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 92);

  size_t data_block_buffer_offset = 0;

  inode->size = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  inode->type = *((char*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(char);

  inode->oid = *((uid_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(uid_t);

  inode->gid = *((gid_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(gid_t);

  inode->perms = *((mode_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(mode_t);

  inode->mtime = *((time_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(time_t);

  inode->hardlinks_count = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  for (size_t i = 0; i < DIRECT_BLOCKS_SIZE; i++) {
    inode->direct_blocks[i] = *((size_t*) (data_block_buffer + data_block_buffer_offset + i * sizeof(size_t)));
  }

  data_block_buffer_offset += DIRECT_BLOCKS_SIZE * sizeof(size_t);

  inode->single_indirect_block = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  inode->double_indirect_block = *((size_t*) (data_block_buffer + data_block_buffer_offset));
  data_block_buffer_offset += sizeof(size_t);

  inode->triple_indirect_block = *((size_t*) (data_block_buffer + data_block_buffer_offset));
}


void write_inode (struct fs_meta* const fsm, const struct fs_inode* const inode) {
  char* const data_block_buffer = fs_malloc(fsm, fsm->block_size * sizeof(char));
  size_t data_block_buffer_offset = 0;

  memset(data_block_buffer, 0, fsm->block_size);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->size, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->type, sizeof(char));
  data_block_buffer_offset += sizeof(char);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->oid, sizeof(uid_t));
  data_block_buffer_offset += sizeof(uid_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->gid, sizeof(gid_t));
  data_block_buffer_offset += sizeof(gid_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->perms, sizeof(mode_t));
  data_block_buffer_offset += sizeof(mode_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->mtime, sizeof(time_t));
  data_block_buffer_offset += sizeof(time_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->hardlinks_count, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->direct_blocks, DIRECT_BLOCKS_SIZE * sizeof(size_t));
  data_block_buffer_offset += DIRECT_BLOCKS_SIZE * sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->single_indirect_block, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->double_indirect_block, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &inode->triple_indirect_block, sizeof(size_t));

  const size_t offset = calc_data_offset(fsm, inode->self_inode_data_block);
  assert(fsm, lseek(fsm->fd, offset, SEEK_SET) == (off_t)offset, 45);
  assert(fsm, write(fsm->fd, data_block_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 56);
}


int is_valid_file_name (struct fs_meta* const fsm, const struct fs_str * const file_name) {
  char* const file_name_c_str = fs_malloc(fsm, (file_name->length + 1) * sizeof(char));

  memcpy(file_name_c_str, file_name->bytes, file_name->length);
  file_name_c_str[file_name->length] = '\0';

  return regexec(&fsm->valid_file_name_pattern, file_name_c_str, 0, NULL, 0) == 0;
}


size_t get_tokens_count (const struct fs_str * const str, const char sep) {
  size_t count = 1;

  for (size_t offset = 0; offset < str->length; offset++) {
    if (str->bytes[offset] == sep) {
      count++;
    }
  }

  return count;
}


void str_split (const struct fs_str * const str, size_t* const tokens_offsets, const char sep) {
  tokens_offsets[0] = 0;

  size_t tokens_offsets_count = 1;

  for (size_t str_offset = 0; str_offset < str->length; str_offset++) {
    if (str_offset < str->length - 1 && str->bytes[str_offset] == sep) {
      tokens_offsets[tokens_offsets_count] = str_offset + 1;

      tokens_offsets_count++;
    }
  }
}


int str_eq (const struct fs_str * const str1, const struct fs_str * const str2) {
  if (str1->length != str2->length) {
    return 0;
  }

  for (size_t i = 0; i < str1->length; i++) {
    if (str1->bytes[i] != str2->bytes[i]) {
      return 0;
    }
  }

  return 1;
}


int dir_get_child_inode_data_block (struct fs_meta* const fsm, const struct fs_inode * const dir_inode, const struct fs_str * const child_name, size_t * const child_data_block) {
  assert_user(fsm, dir_inode->type == 'd', 89, "Invalid path!");

  const size_t content_blocks = dir_inode->size / fsm->block_size + 1;
  const size_t dir_content_size = content_blocks * fsm->block_size * sizeof(char);
  const struct fs_str dir_content = { fs_malloc(fsm, dir_content_size), dir_content_size };

  read_entire_file(fsm, dir_inode, &dir_content);

  size_t content_bytes_checked = 0;

  int child_found = 0;

  while (content_bytes_checked < dir_inode->size) {
    size_t current_child_length = *((size_t*) (dir_content.bytes + content_bytes_checked));
    content_bytes_checked += sizeof(size_t); // passing info about file name length


    const struct fs_str current_child_name = { dir_content.bytes + content_bytes_checked, current_child_length };

    if (str_eq(child_name, &current_child_name)) {
      if (child_data_block != NULL) {
        *child_data_block = *((size_t*)(dir_content.bytes + content_bytes_checked + current_child_length));
      }

      child_found = 1;
      break;
    }

    content_bytes_checked += current_child_length; // passing file name
    content_bytes_checked += sizeof(size_t); // passing inode address
  }

  return child_found;
}


void dir_add_file (struct fs_meta* const fsm, struct fs_inode * const dir_inode, const struct fs_str * const file_name, const size_t file_addr) {
  const size_t new_file_name_length_size = sizeof(size_t);
  const size_t new_file_address_size = sizeof(size_t);
  const size_t new_parent_dir_size = dir_inode->size + new_file_name_length_size + file_name->length + new_file_address_size;
  const size_t new_parent_dir_content_blocks = new_parent_dir_size / fsm->block_size + 1;

  assert_user(fsm, is_valid_file_name(fsm, file_name), 30, "Invalid file name!");
  assert_user(fsm, dir_get_child_inode_data_block(fsm, dir_inode, file_name, NULL) == 0, 73, "File already exists!");

  const size_t content_blocks = dir_inode->size / fsm->block_size + 1;
  const size_t dir_content_size = content_blocks * fsm->block_size * sizeof(char);
  const struct fs_str dir_content = { fs_malloc(fsm, dir_content_size), dir_content_size };
  read_entire_file(fsm, dir_inode, &dir_content);

  char* const new_parent_dir_content = fs_malloc(fsm, new_parent_dir_content_blocks * fsm->block_size);
  memset(new_parent_dir_content, 0, new_parent_dir_content_blocks * fsm->block_size);

  memcpy(new_parent_dir_content, dir_content.bytes, dir_inode->size);
  memcpy(new_parent_dir_content + dir_inode->size, (char*) &file_name->length, new_file_name_length_size);
  memcpy(new_parent_dir_content + dir_inode->size + new_file_name_length_size, file_name->bytes, file_name->length);
  memcpy(new_parent_dir_content + dir_inode->size + new_file_name_length_size + file_name->length, (char*) &file_addr, new_file_address_size);

  const struct fs_str new_parent_dir_content_str = { new_parent_dir_content, new_parent_dir_size };
  write_to_file(fsm, dir_inode, &new_parent_dir_content_str);
  write_inode(fsm, dir_inode);
}


void dir_rm_file (struct fs_meta* const fsm, struct fs_inode* const dir_inode, const struct fs_str* const file_name, const int is_dir) {
  const size_t content_blocks = dir_inode->size / fsm->block_size + 1;
  const size_t dir_content_size = content_blocks * fsm->block_size * sizeof(char);
  const struct fs_str dir_content = { fs_malloc(fsm, dir_content_size), dir_content_size };

  read_entire_file(fsm, dir_inode, &dir_content);

  const size_t old_dir_content_blocks = dir_inode->size / fsm->block_size + 1;
  char* const new_dir_content = fs_malloc(fsm, old_dir_content_blocks * fsm->block_size);

  size_t content_bytes_checked = 0;
  size_t file_entry_offset = 0;
  int child_found = 0;
  size_t child_inode_addr;

  while (content_bytes_checked < dir_inode->size) {
    size_t current_child_length = *((size_t*) (dir_content.bytes + content_bytes_checked));
    content_bytes_checked += sizeof(size_t); // passing info about file name length

    const struct fs_str current_child_name = { dir_content.bytes + content_bytes_checked, current_child_length };

    content_bytes_checked += current_child_length; // passing file name

    child_inode_addr = *((size_t*) (dir_content.bytes + content_bytes_checked));

    content_bytes_checked += sizeof(size_t); // passing inode address

    if (str_eq(file_name, &current_child_name)) {
      child_found = 1;

      break;
    }

    file_entry_offset += 2 * sizeof(size_t) + current_child_length;
  }

  assert_user(fsm, child_found, 50, "Target file not found!");

  struct fs_inode target_inode;
  read_inode(fsm, child_inode_addr, &target_inode);
  assert_user(fsm, (is_dir && target_inode.type == 'd') || (!is_dir && target_inode.type != 'd'), 71, is_dir ? "Target file is not a dir!" : "Can't use command rmfile to remove a directory!");
  assert_user(fsm, target_inode.type != 'd' || target_inode.size == 0, 72, "Target dir is not empty!");

  assert(fsm, target_inode.hardlinks_count > 0, 130);

  target_inode.hardlinks_count--;

  if (target_inode.hardlinks_count == 0) {
    inode_free_all_data_blocks(fsm, &target_inode);

    set_block_status(fsm, target_inode.self_inode_data_block, 0);
  } else {
    write_inode(fsm, &target_inode);
  }

  const size_t new_dir_size = file_entry_offset + (dir_inode->size - content_bytes_checked);
  const size_t new_dir_content_blocks = new_dir_size / fsm->block_size + 1;

  memset(new_dir_content, 0, new_dir_content_blocks * fsm->block_size);

  memcpy(new_dir_content, dir_content.bytes, file_entry_offset);
  memcpy(new_dir_content + file_entry_offset, dir_content.bytes + content_bytes_checked, dir_inode->size - content_bytes_checked);

  const struct fs_str new_dir_content_str = { new_dir_content, new_dir_size };

  write_to_file(fsm, dir_inode, &new_dir_content_str);
  write_inode(fsm, dir_inode);
}


int get_inode (struct fs_meta* const fsm, const struct fs_str * const path, struct fs_inode* const inode) {
  assert_user(fsm, path->length >= 1, 85, "Invalid path!");

  int result_must_be_dir = path->bytes[path->length - 1] == fsm->dir_sep;

  const size_t sanitized_path_length = result_must_be_dir ? path->length - 1 : path->length;
  const struct fs_str sanitized_path = { path->bytes , sanitized_path_length };

  const size_t tokens_count = get_tokens_count(&sanitized_path, fsm->dir_sep);

  size_t* const tokens_offsets = fs_malloc(fsm, tokens_count * sizeof(size_t));

  str_split(&sanitized_path, tokens_offsets, fsm->dir_sep);

  assert_user(fsm, path->bytes[0] == fsm->root_dir_label, 86, "Invalid path!");
  assert_user(fsm, sanitized_path.length == 1 || sanitized_path.bytes[1] == fsm->dir_sep, 88, "Invalid path!");

  struct fs_inode result_inode;
  read_inode(fsm, fsm->root_dir_inode_data_block, &result_inode);

  for (size_t token = 1; token < tokens_count; token++) {
    const size_t token_start = tokens_offsets[token];
    const size_t token_end = (token == tokens_count - 1) ? sanitized_path_length : tokens_offsets[token + 1] - 1;

    const struct fs_str child_name = { path->bytes + tokens_offsets[token], token_end - token_start };

    size_t child_data_block;

    if (!dir_get_child_inode_data_block(fsm, &result_inode, &child_name, &child_data_block)) {
      return 0;
    }

    struct fs_inode child_inode;
    read_inode(fsm, child_data_block, &child_inode);

    result_inode = child_inode;
  }

  *inode = result_inode;

  assert_user(fsm, !result_must_be_dir || result_inode.type == 'd', 87, "Target file is not a dir!");

  return 1;
}


size_t fsck_mark_content_data_blocks (struct fs_meta* const fsm, unsigned char * const reachable_data_blocks_bitmap, const int level, const size_t data_block, const size_t blocks_to_read, const size_t blocks_read) {
  assert(fsm, level >= 0 && level <= 3, 49);
  assert(fsm, blocks_read < blocks_to_read, 74);

  size_t data_offset = calc_data_offset(fsm, data_block);

  assert(fsm, lseek(fsm->fd, data_offset, SEEK_SET) == (off_t)data_offset, 82);

  size_t current_blocks_read = 0;

  if (level == 0) {
    current_blocks_read++;
  } else if (level >= 1 && level <= 3) {
     char* const data_block_addresses_buffer = fs_malloc(fsm, fsm->block_size * sizeof(char));

    assert(fsm, read(fsm->fd, (char*) data_block_addresses_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 61);

    const size_t data_block_addresses_to_read = fsm->block_size / sizeof(size_t);
    size_t data_block_addresses_read = 0;

    while (blocks_read + current_blocks_read < blocks_to_read && data_block_addresses_read < data_block_addresses_to_read) {
      const size_t next_data_block = *((size_t*) (data_block_addresses_buffer + data_block_addresses_read * sizeof(size_t)));

      current_blocks_read += fsck_mark_content_data_blocks(fsm, reachable_data_blocks_bitmap, level - 1, next_data_block, blocks_to_read, blocks_read + current_blocks_read);
      data_block_addresses_read++;
    }
  } else {
    assert(fsm, 0, 83);
  }

  const size_t bitmap_info_byte_offset = data_block / BITS_IN_BYTE;
  const size_t bitmap_info_byte_bit_offset = data_block % BITS_IN_BYTE;

  set_bit(fsm, reachable_data_blocks_bitmap + bitmap_info_byte_offset, bitmap_info_byte_bit_offset, 1);

  return current_blocks_read;
}


void fsck_all_inodes(struct fs_meta* const fsm, unsigned char * const reachable_data_blocks_bitmap, const size_t inode_data_block) {
  const size_t bitmap_info_byte_offset = inode_data_block / BITS_IN_BYTE;
  const size_t bitmap_info_byte_bit_offset = inode_data_block % BITS_IN_BYTE;
  const size_t bitshifts = BITS_IN_BYTE - bitmap_info_byte_bit_offset - 1;

  if ((reachable_data_blocks_bitmap[bitmap_info_byte_offset] >> bitshifts) % 2 == 1) {
    return;
  }

  set_bit(fsm, reachable_data_blocks_bitmap + bitmap_info_byte_offset, bitmap_info_byte_bit_offset, 1);

  struct fs_inode inode;
  read_inode(fsm, inode_data_block, &inode);

  assert_user(fsm, inode.type == '-' || inode.type == 'd' || inode.type == 'l', 96, "Inode found with an invalid type!");

  const size_t blocks_to_read = inode.size / fsm->block_size + 1;
  size_t blocks_read = 0;

  while (blocks_read < blocks_to_read && blocks_read < DIRECT_BLOCKS_SIZE) {
    blocks_read += fsck_mark_content_data_blocks(fsm, reachable_data_blocks_bitmap, 0, inode.direct_blocks[blocks_read], blocks_to_read, blocks_read);
  }

  if (blocks_read < blocks_to_read) {
    blocks_read += fsck_mark_content_data_blocks(fsm, reachable_data_blocks_bitmap, 1, inode.single_indirect_block, blocks_to_read, blocks_read);
  }

  if (blocks_read < blocks_to_read) {
    blocks_read += fsck_mark_content_data_blocks(fsm, reachable_data_blocks_bitmap, 2, inode.double_indirect_block, blocks_to_read, blocks_read);
  }

  if (blocks_read < blocks_to_read) {
    blocks_read += fsck_mark_content_data_blocks(fsm, reachable_data_blocks_bitmap, 3, inode.triple_indirect_block, blocks_to_read, blocks_read);
  }

  if (inode.type != 'd') {
    return;
  }

  const size_t content_blocks = inode.size / fsm->block_size + 1;
  const size_t dir_content_size = content_blocks * fsm->block_size * sizeof(char);
  const struct fs_str dir_content = { fs_malloc(fsm, dir_content_size), dir_content_size };

  read_entire_file(fsm, &inode, &dir_content);

  size_t content_read = 0;

  while (content_read < inode.size) {
    const size_t file_name_size = *((size_t*) (dir_content.bytes + content_read));
    content_read += sizeof(size_t);

    const struct fs_str file_name = { dir_content.bytes + content_read, file_name_size };
    assert_user(fsm, is_valid_file_name(fsm, &file_name), 100, "File with an invalid name found!");
    content_read += file_name_size;

    const size_t child_data_block = *((size_t*) (dir_content.bytes + content_read));
    fsck_all_inodes(fsm, reachable_data_blocks_bitmap, child_data_block);

    content_read += sizeof(size_t);
  }
}


void print_perms (const mode_t perms) {
  printf((perms & S_IRUSR) ? "r" : "-");
  printf((perms & S_IWUSR) ? "w" : "-");
  printf((perms & S_IXUSR) ? "x" : "-");
  printf((perms & S_IRGRP) ? "r" : "-");
  printf((perms & S_IWGRP) ? "w" : "-");
  printf((perms & S_IXGRP) ? "x" : "-");
  printf((perms & S_IROTH) ? "r" : "-");
  printf((perms & S_IWOTH) ? "w" : "-");
  printf((perms & S_IXOTH) ? "x" : "-");
}


void print_mtime (struct fs_meta* const fsm, const time_t* const mtime) {
  const size_t ISO8601_FORMAT_SIZE = sizeof("YYYY-MM-DDTHH:MM:SSZ");
  char timestamp[ISO8601_FORMAT_SIZE];

  struct tm* utc_mtime = gmtime(mtime);
  assert(fsm, utc_mtime != NULL, 34);
  assert(fsm, strftime(timestamp, ISO8601_FORMAT_SIZE, "%Y-%m-%dT%H:%M:%SZ", utc_mtime) == ISO8601_FORMAT_SIZE - 1, 37);
  const struct fs_str timestamp_iso8601 = { timestamp, ISO8601_FORMAT_SIZE - 1 };
  str_print(&timestamp_iso8601);
}


void print_file_meta (struct fs_meta* const fsm, const struct fs_inode* inode, const struct fs_str * const file_name) {
  printf("%c", inode->type);
  print_perms(inode->perms);
  printf(" ");

  struct passwd* owner = getpwuid(inode->oid);

  if (owner != NULL) {
    const struct fs_str owner_name = { owner->pw_name, strlen(owner->pw_name) };
    str_print(&owner_name);
  }

  struct group* grp = getgrgid(inode->gid);

  if (grp != NULL) {
    const struct fs_str group_name = { grp->gr_name, strlen(grp->gr_name) };
    printf(" ");
    str_print(&group_name);
  }

  printf(" %lu ", (unsigned long)inode->size);
  print_mtime(fsm, &inode->mtime);
  printf(" ");

  str_print(file_name);

  printf("\n");
}


void print_dir_content (struct fs_meta* const fsm, const struct fs_inode* dir_inode) {
  assert_user(fsm, dir_inode->type == 'd', 32, "Target file is not a directory!");

  const size_t content_blocks = dir_inode->size / fsm->block_size + 1;
  const size_t dir_content_size = content_blocks * fsm->block_size * sizeof(char);
  const struct fs_str dir_content = { fs_malloc(fsm, dir_content_size), dir_content_size };

  read_entire_file(fsm, dir_inode, &dir_content);

  size_t content_read = 0;

  while (content_read < dir_inode->size) {
    const size_t file_name_size = *((size_t*) (dir_content.bytes + content_read));
    content_read += sizeof(size_t);

    const size_t child_data_block = *((size_t*) (dir_content.bytes + content_read + file_name_size));

    struct fs_inode child_inode;
    read_inode(fsm, child_data_block, &child_inode);

    const struct fs_str file_name = { dir_content.bytes + content_read, file_name_size };

    print_file_meta(fsm, &child_inode, &file_name);

    content_read += file_name_size;
    content_read += sizeof(size_t);
  }
}

void print_free_blocks_bitmap(struct fs_meta* const fsm) {
  printf("free_blocks_bitmap=");

  const size_t offset = fsm->bitmap_info_blocks_start * fsm->block_size;

  assert(fsm, lseek(fsm->fd, offset, SEEK_SET) == (off_t)offset, 70);

  size_t data_block = 0;

  while (data_block < fsm->data_blocks_count) {
    unsigned char data_block_byte;

    assert(fsm, read(fsm->fd, &data_block_byte, 1) == 1, 112);

    for (int i = 0; i < BITS_IN_BYTE && data_block < fsm->data_blocks_count; i++, data_block++) {
      if ((data_block_byte >> (BITS_IN_BYTE - i - 1)) % 2 == 0) {
        printf("0");
      } else {
        printf("1");
      }
    }

    printf("(%lu) ", (unsigned long)data_block);
  }

  printf("\n");
}


void fs_mkfs (char * fs_path) {
  const char ROOT_DIR_LABEL = '+';
  const char DIR_SEP = '/';

  const int fd = open(fs_path, O_RDWR);

  if (fd < 0) {
    printf("ERROR!\n");
    exit(26);
  }

  struct fs_meta* fsm = (struct fs_meta*) malloc(sizeof(struct fs_meta));

  if (fsm == NULL) {
    printf("ERROR!\n");
    close(fd);
    exit(33);
  }

  struct stat statbuf;

  if (fstat(fd, &statbuf) < 0) {
    close(fd);
    exit(16);
  }

  fsm->fd = fd;
  fsm->fs_path = fs_path;
  fsm->root_dir_label = ROOT_DIR_LABEL;
  fsm->dir_sep = DIR_SEP;
  fsm->block_size = BLOCK_SIZE;
  fsm->superblock = 0;
  fsm->fs_total_blocks_count = statbuf.st_size / fsm->block_size;
  fsm->next_free_data_block = 1;
  fsm->bitmap_info_blocks_start = 1;
  fsm->root_dir_inode_data_block = 0;
  fsm->gbc.ptrs_to_free_size = 0;
  fsm->gbc.ptrs_to_free_count = 0;
  fsm->gbc.ptrs_to_free = NULL;
  fsm->gbc.fds_to_close_size = 0;
  fsm->gbc.fds_to_close_count = 0;
  fsm->gbc.fds_to_close = NULL;

  calc_free_block_bitmap_size(statbuf.st_size / fsm->block_size, &fsm->bitmap_info_blocks_count, &fsm->data_blocks_count);

  fsm->data_blocks_start = 1 + fsm->bitmap_info_blocks_count;

  if (regcomp(&fsm->valid_file_name_pattern, VALID_FILENAME_PATTERN, REG_EXTENDED | REG_NOSUB) != 0) {
    printf("ERROR!\n");
    close(fsm->fd);
    free(fsm);
    exit(31);
  }

  close_before_exit(fsm, fsm->fd);

  char* const data_block_buffer = fs_malloc(fsm, fsm->block_size * sizeof(char));
  size_t data_block_buffer_offset = 0;

  memset(data_block_buffer, 0, fsm->block_size);

  memcpy(data_block_buffer + data_block_buffer_offset, &ROOT_DIR_LABEL, sizeof(char));
  data_block_buffer_offset += sizeof(char);

  memcpy(data_block_buffer + data_block_buffer_offset, &DIR_SEP, sizeof(char));
  data_block_buffer_offset += sizeof(char);

  memcpy(data_block_buffer + data_block_buffer_offset, &fsm->block_size, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &fsm->superblock, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &fsm->bitmap_info_blocks_start, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &fsm->bitmap_info_blocks_count, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &fsm->data_blocks_count, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &fsm->fs_total_blocks_count, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &fsm->data_blocks_start, sizeof(size_t));
  data_block_buffer_offset += sizeof(size_t);

  memcpy(data_block_buffer + data_block_buffer_offset, &fsm->root_dir_inode_data_block, sizeof(size_t));

  assert(fsm, write(fsm->fd, data_block_buffer, fsm->block_size) == (ssize_t)fsm->block_size, 24);

  char* zeroes = fs_malloc(fsm, fsm->block_size);

  memset(zeroes, 0, fsm->block_size);

  for (size_t blocks_written = 0; blocks_written < fsm->bitmap_info_blocks_count; blocks_written++) {
    assert(fsm, write(fsm->fd, zeroes, fsm->block_size) == (ssize_t)fsm->block_size, 36);
  }

  set_block_status(fsm, 0, 1);

  struct fs_inode root_dir_inode;
  create_empty_inode(fsm, &root_dir_inode, 0, 'd');

  write_inode(fsm, &root_dir_inode);

  assert(fsm, fsync(fsm->fd) == 0, 25);

  destroy_fs_meta(fsm);
}


void fs_fsck (struct fs_meta* const fsm) {
  assert_fsck(fsm, fsm->root_dir_label == '+', 101, "Checking root dir label");
  assert_fsck(fsm, fsm->dir_sep == '/', 102, "Checking dir separator");
  assert_fsck(fsm, fsm->block_size == BLOCK_SIZE, 103, "Checking block size");
  assert_fsck(fsm, fsm->root_dir_inode_data_block <= fsm->data_blocks_count, 104, "Checking root dir inode data block");
  assert_fsck(fsm, fsm->superblock == 0, 105, "Checking superblock location");
  assert_fsck(fsm, fsm->bitmap_info_blocks_start == 1, 106, "Checking start of bitmap info blocks");
  assert_fsck(fsm, fsm->bitmap_info_blocks_count + fsm->data_blocks_count + 1 == fsm->fs_total_blocks_count, 107, "Checking total blocks count");

  unsigned char* reachable_data_blocks_bitmap = fs_malloc(fsm, fsm->bitmap_info_blocks_count * fsm->block_size);

  memset(reachable_data_blocks_bitmap, 0, fsm->bitmap_info_blocks_count * fsm->block_size);

  printf("Checking all inodes ... ");

  fsck_all_inodes(fsm, reachable_data_blocks_bitmap, fsm->root_dir_inode_data_block);

  printf("OK\n");

  unsigned char* bitmap_info = fs_malloc(fsm, fsm->bitmap_info_blocks_count * fsm->block_size);

  assert(fsm, lseek(fsm->fd, fsm->bitmap_info_blocks_start * fsm->block_size, SEEK_SET) == (off_t) (fsm->bitmap_info_blocks_start * fsm->block_size), 94);
  assert(fsm, read(fsm->fd, bitmap_info, fsm->bitmap_info_blocks_count * fsm->block_size) == (ssize_t) (fsm->bitmap_info_blocks_count * fsm->block_size), 95);

  printf("Checking bitmap info blocks ... ");

  for (size_t i = 0; i < fsm->bitmap_info_blocks_count * fsm->block_size; i++) {
    assert_user(fsm, reachable_data_blocks_bitmap[i] == bitmap_info[i], 108, "Bitmap info blocks does not correctly store the information about free data blocks!");
  }

  printf("OK\n");

  assert_fsck(fsm, fsm->next_free_data_block <= fsm->data_blocks_count, 109, "Checking next free data block (1)");

  const size_t bitmap_info_byte_offset = fsm->next_free_data_block / BITS_IN_BYTE;
  const size_t bitmap_info_byte_bit_offset = fsm->next_free_data_block % BITS_IN_BYTE;

  const size_t bitshifts = BITS_IN_BYTE - bitmap_info_byte_bit_offset - 1;

  assert_fsck(fsm, (bitmap_info[bitmap_info_byte_offset] >> bitshifts) % 2 == 0, 110, "Checking next free data block (2)");

  printf("fsck finished. No errors found!\n");
}


void fs_debug (struct fs_meta* const fsm) {
  printf("root_dir_label=%c\n", fsm->root_dir_label);
  printf("dir_sep=%c\n", fsm->dir_sep);
  printf("block_size=%lu\n", (unsigned long)fsm->block_size);
  printf("superblock=%lu\n", (unsigned long)fsm->superblock);
  printf("bitmap_info_blocks_start=%lu\n", (unsigned long)fsm->bitmap_info_blocks_start);
  printf("bitmap_info_blocks_count=%lu\n", (unsigned long)fsm->bitmap_info_blocks_count);
  printf("data_blocks_count=%lu\n", (unsigned long)fsm->data_blocks_count);
  printf("fs_total_blocks_count=%lu\n", (unsigned long)fsm->fs_total_blocks_count);
  printf("data_blocks_start=%lu\n", (unsigned long)fsm->data_blocks_start);

  print_free_blocks_bitmap(fsm);
}


void fs_lsobj (struct fs_meta* const fsm, char * const target_file) {
  const size_t target_file_length = strlen(target_file);
  const size_t sanitized_target_file_length = (target_file[target_file_length - 1] == fsm->dir_sep) ? target_file_length - 1 : target_file_length;

  const struct fs_str sanitized_target_file = { target_file, sanitized_target_file_length };

  struct fs_inode file_inode;

  assert_user(fsm, get_inode(fsm, &sanitized_target_file, &file_inode), 70, "Target file not found!");

  print_file_meta(fsm, &file_inode, &sanitized_target_file);
}


void fs_lsdir (struct fs_meta* const fsm, char * const target_dir) {
  const size_t target_dir_length = strlen(target_dir);
  const size_t sanitized_target_dir_length = (target_dir[target_dir_length - 1] == fsm->dir_sep) ? target_dir_length - 1 : target_dir_length;

  const struct fs_str sanitized_target_dir = { target_dir, sanitized_target_dir_length };

  const size_t tokens_count = get_tokens_count(&sanitized_target_dir, fsm->dir_sep);

  assert_user(fsm, tokens_count > 0, 55, "Invalid path!");

  struct fs_inode inode;

  assert_user(fsm, get_inode(fsm, &sanitized_target_dir, &inode), 54, "Target dir not found!");

  print_dir_content(fsm, &inode);
}


void fs_stat (struct fs_meta* const fsm, char * const target_file) {
  const size_t target_file_length = strlen(target_file);
  const size_t sanitized_target_file_length = (target_file[target_file_length - 1] == fsm->dir_sep) ? target_file_length - 1 : target_file_length;

  const struct fs_str sanitized_target_file = { target_file, sanitized_target_file_length };

  struct fs_inode file_inode;
  assert_user(fsm, get_inode(fsm, &sanitized_target_file, &file_inode), 124, "Target file not found!");

  printf("File: ");
  str_print(&sanitized_target_file);
  printf("\nSize: %lu\n", (unsigned long) file_inode.size);
  printf("Blocks: %lu\n", (unsigned long) (file_inode.size / fsm->block_size + 1));
  printf("Type: ");

  if (file_inode.type == '-') {
    printf("regular file\n");
  } else if (file_inode.type == 'd') {
    printf("directory\n");
  } else if (file_inode.type == 'l') {
    printf("symbolic link\n");
  }

  printf("Inode: %lu", (unsigned long) file_inode.self_inode_data_block);
  printf("\nAccess: ");
  print_perms(file_inode.perms);
  printf("\nOwner: (");

  struct passwd* owner = getpwuid(file_inode.oid);

  if (owner == NULL) {
    printf("???");
  } else {
    const struct fs_str owner_name = { owner->pw_name, strlen(owner->pw_name) };
    str_print(&owner_name);
  }

  printf("/%lu)\n", (unsigned long) file_inode.oid);

  printf("Group: (");

  struct group* grp = getgrgid(file_inode.gid);

  if (grp == NULL) {
    printf("???");
  } else {
    const struct fs_str group_name = { grp->gr_name, strlen(grp->gr_name) };
    str_print(&group_name);
  }

  printf("/%lu)\n", (unsigned long) file_inode.gid);

  printf("Mtime: ");
  print_mtime(fsm, &file_inode.mtime);
  printf("\n");

  printf("Hard links: %lu\n", (unsigned long) file_inode.hardlinks_count);
}

void fs_mkdir (struct fs_meta* const fsm, char * const target_dir) {
  allow_write(fsm);

  //  read parent dir inode
  const size_t target_dir_length = strlen(target_dir);
  const size_t sanitized_target_dir_length = (target_dir[target_dir_length - 1] == fsm->dir_sep) ? target_dir_length - 1 : target_dir_length;

  const struct fs_str sanitized_target_dir = { target_dir, sanitized_target_dir_length };

  const size_t tokens_count = get_tokens_count(&sanitized_target_dir, fsm->dir_sep);

  assert_user(fsm, tokens_count > 1, 22, "Target dir must be an ancestor on root dir!");

  size_t * const tokens_offsets = fs_malloc(fsm, tokens_count * sizeof(size_t));

  str_split(&sanitized_target_dir, tokens_offsets, fsm->dir_sep);

  struct fs_inode parent_inode;

  const size_t path_length = tokens_offsets[tokens_count - 1] - 1;

  const struct fs_str parent_target_dir = { target_dir, path_length };

  assert_user(fsm, get_inode(fsm, &parent_target_dir, &parent_inode), 23, "Invalid target path!");

  // get free block
  const size_t new_dir_inode_free_block = get_free_data_block(fsm);
  set_block_status(fsm, new_dir_inode_free_block, 1);

  // write new dir inode

  struct fs_inode new_dir_inode;
  create_empty_inode(fsm, &new_dir_inode, new_dir_inode_free_block, 'd');

  write_inode(fsm, &new_dir_inode);

  // modify parent dir content
  const size_t new_dir_name_length = sanitized_target_dir.length - tokens_offsets[tokens_count - 1];
  const struct fs_str new_dir_name = { target_dir + tokens_offsets[tokens_count - 1], new_dir_name_length };

  dir_add_file(fsm, &parent_inode, &new_dir_name, new_dir_inode_free_block);
}


void fs_cpfile (struct fs_meta* const fsm, char * const src_file, char * const dest_file) {
  const int in = strlen(dest_file) > 2 && dest_file[0] == fsm->root_dir_label && dest_file[1] == fsm->dir_sep;
  const int out = strlen(src_file) > 2 && src_file[0] == fsm->root_dir_label && src_file[1] == fsm->dir_sep;

  assert_user(fsm, (in && !out) || (!in && out), 20, "Either source or destination path must point to file in block device! A path that points to file in block device begins with '+/'.");

  char* const fs_file = in ? dest_file : src_file;

  const size_t fs_file_length = strlen(fs_file);
  const size_t sanitized_fs_file_length = (fs_file[fs_file_length - 1] == fsm->dir_sep) ? fs_file_length - 1 : fs_file_length;

  const struct fs_str sanitized_fs_file = { fs_file, sanitized_fs_file_length };

  const size_t tokens_count = get_tokens_count(&sanitized_fs_file, fsm->dir_sep);

  assert(fsm, tokens_count > 1, 21);

  size_t * const tokens_offsets = fs_malloc(fsm, tokens_count * sizeof(size_t));

  str_split(&sanitized_fs_file, tokens_offsets, fsm->dir_sep);

  const size_t path_length = tokens_offsets[tokens_count - 1] - 1;

  const struct fs_str parent_fs_file = { fs_file, path_length };

  if (in) {
    allow_write(fsm);

    const int src_fd = fs_open(fsm, src_file, O_RDONLY, 0);

    struct stat statbuf;
    assert(fsm, fstat(src_fd, &statbuf) == 0, 18);

    const size_t file_content_buffer_size = (statbuf.st_size / fsm->block_size + 1) * fsm->block_size;
    char* const file_content_buffer = fs_malloc(fsm, file_content_buffer_size);
    memset(file_content_buffer, 0, file_content_buffer_size);

    assert(fsm, read(src_fd, file_content_buffer, statbuf.st_size) == statbuf.st_size, 19);

    struct fs_inode parent_fs_file_inode;
    assert_user(fsm, get_inode(fsm, &parent_fs_file, &parent_fs_file_inode), 16, "Invalid destination!");
    assert_user(fsm, parent_fs_file_inode.type == 'd', 17, "Invalid destination!");

    struct fs_inode dest_inode;

    if (!get_inode(fsm, &sanitized_fs_file, &dest_inode)) {
      const size_t content_blocks = parent_fs_file_inode.size / fsm->block_size + 1;
      const size_t parent_dir_content_size = content_blocks * fsm->block_size * sizeof(char);
      const struct fs_str parent_dir_content = { fs_malloc(fsm, parent_dir_content_size), parent_dir_content_size };

      read_entire_file(fsm, &parent_fs_file_inode, &parent_dir_content);

      const size_t dest_inode_free_block = get_free_data_block(fsm);
      set_block_status(fsm, dest_inode_free_block, 1);

      create_empty_inode(fsm, &dest_inode, dest_inode_free_block, '-');

      const size_t new_file_name_length = sanitized_fs_file.length - tokens_offsets[tokens_count - 1];
      const struct fs_str new_file_name = { fs_file + tokens_offsets[tokens_count - 1], new_file_name_length };

      dir_add_file(fsm, &parent_fs_file_inode, &new_file_name, dest_inode_free_block);
    }

    dest_inode.oid = statbuf.st_uid;
    dest_inode.gid = statbuf.st_gid;
    dest_inode.perms = statbuf.st_mode;

    const struct fs_str file_content = { file_content_buffer, statbuf.st_size };

    write_to_file(fsm, &dest_inode, &file_content);
    write_inode(fsm, &dest_inode);
  } else if (out) {
    struct fs_inode src_inode;
    assert_user(fsm, get_inode(fsm, &sanitized_fs_file, &src_inode), 13, "Source file does not exist!");

    const int dest_fd = fs_open(fsm, dest_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    const size_t content_blocks = src_inode.size / fsm->block_size + 1;
    const size_t file_content_size = content_blocks * fsm->block_size * sizeof(char);

    const struct fs_str file_content = { fs_malloc(fsm, file_content_size), file_content_size };

    read_entire_file(fsm, &src_inode, &file_content);

    assert(fsm, write(dest_fd, file_content.bytes, src_inode.size) == (ssize_t) src_inode.size, 14);

    assert(fsm, fsync(dest_fd) == 0, 12);
  } else {
    assert(fsm, 0, 15);
  }
}


void fs_rm (struct fs_meta* const fsm, char * const target_file, const int is_dir) {
  allow_write(fsm);

  const size_t target_file_length = strlen(target_file);
  const size_t sanitized_target_file_length = (target_file[target_file_length - 1] == fsm->dir_sep) ? target_file_length - 1 : target_file_length;

  const struct fs_str sanitized_target_file = { target_file, sanitized_target_file_length };
  const size_t tokens_count = get_tokens_count(&sanitized_target_file, fsm->dir_sep);

  assert_user(fsm, tokens_count > 1, 4, "Target file must be a child of the root dir!");

  size_t * const tokens_offsets = fs_malloc(fsm, tokens_count * sizeof(size_t));
  str_split(&sanitized_target_file, tokens_offsets, fsm->dir_sep);

  const size_t parent_dir_path_length = tokens_offsets[tokens_count - 1] - 1;
  const struct fs_str parent_target_dir = { target_file, parent_dir_path_length };

  struct fs_inode parent_inode;
  assert_user(fsm, get_inode(fsm, &parent_target_dir, &parent_inode), 90, "Invalid path!");

  const struct fs_str child_name = { target_file + parent_dir_path_length + 1, sanitized_target_file_length - parent_dir_path_length - 1 };

  dir_rm_file(fsm, &parent_inode, &child_name, is_dir);
}


void fs_rmfile (struct fs_meta* const fsm, char* const target_file) {
  fs_rm(fsm, target_file, 0);
}


void fs_rmdir (struct fs_meta* const fsm, char* const target_dir) {
  fs_rm(fsm, target_dir, 1);
}


void fs_chmod (struct fs_meta* const fsm, char* const access_mode, char* const target_file) {
  allow_write(fsm);

  const size_t ACCESS_MODE_LENGTH = 9;
  const size_t PERMS_GROUPS = 3;
  const size_t PERMS_ACTIONS = 3;
  assert_user(fsm, strlen(access_mode) == ACCESS_MODE_LENGTH, 115, "Invalid access mode rule!");

  for (size_t i = 0; i < PERMS_GROUPS; i++) {
    assert_user(fsm, access_mode[i * PERMS_ACTIONS] == 'r' || access_mode[i * PERMS_ACTIONS] == '-', 117, "Inalid access mode rule!");
    assert_user(fsm, access_mode[i * PERMS_ACTIONS + 1] == 'w' || access_mode[i * PERMS_ACTIONS + 1] == '-', 118, "Invalid access mode rule!");
    assert_user(fsm, access_mode[i * PERMS_ACTIONS + 2] == 'x' || access_mode[i * PERMS_ACTIONS + 2] == '-', 119, "Invalid access mode rule!");
  }

  const size_t target_file_length = strlen(target_file);
  const size_t sanitized_target_file_length = (target_file[target_file_length - 1] == fsm->dir_sep) ? target_file_length - 1 : target_file_length;

  const struct fs_str sanitized_target_file = { target_file, sanitized_target_file_length };

  struct fs_inode inode;
  assert_user(fsm, get_inode(fsm, &sanitized_target_file, &inode), 116, "Target not found!");

  mode_t new_perms = 0;
  new_perms |= access_mode[0] == 'r' ? S_IRUSR : 0;
  new_perms |= access_mode[1] == 'w' ? S_IWUSR : 0;
  new_perms |= access_mode[2] == 'x' ? S_IXUSR : 0;
  new_perms |= access_mode[3] == 'r' ? S_IRGRP : 0;
  new_perms |= access_mode[4] == 'w' ? S_IWGRP : 0;
  new_perms |= access_mode[5] == 'x' ? S_IXGRP : 0;
  new_perms |= access_mode[6] == 'r' ? S_IROTH : 0;
  new_perms |= access_mode[7] == 'w' ? S_IWOTH : 0;
  new_perms |= access_mode[8] == 'x' ? S_IXOTH : 0;

  inode.perms = new_perms;

  write_inode(fsm, &inode);
}


void fs_chown (struct fs_meta* const fsm, char* const owner_and_group, char* const target_file) {
  allow_write(fsm);

  const char OWNER_AND_GROUP_SEP = ':';
  const size_t owner_and_group_str_length = strlen(owner_and_group);
  const struct fs_str owner_and_group_str = { owner_and_group, owner_and_group_str_length };
  const size_t tokens_count = get_tokens_count(&owner_and_group_str, OWNER_AND_GROUP_SEP);

  assert(fsm, tokens_count == 2, 120);

  size_t* const tokens_offsets = fs_malloc(fsm, tokens_count * sizeof(size_t));
  str_split(&owner_and_group_str, tokens_offsets, OWNER_AND_GROUP_SEP);

  const size_t owner_str_length = tokens_offsets[1] - 1;
  const size_t group_str_length = owner_and_group_str_length - tokens_offsets[1];

  char* const owner_str = fs_malloc(fsm, owner_str_length + 1);
  char* const group_str = fs_malloc(fsm, group_str_length + 1);

  memcpy(owner_str, owner_and_group, owner_str_length);
  memcpy(group_str, owner_and_group + tokens_offsets[1], group_str_length);

  owner_str[owner_str_length] = '\0';
  group_str[group_str_length] = '\0';

  struct passwd* owner_fields = getpwnam(owner_str);
  assert_user(fsm, owner_fields != NULL, 121, "Invalid user name!");

  struct group* group_fields = getgrnam(group_str);
  assert_user(fsm, group_fields != NULL, 122, "Invalid group name!");

  const size_t target_file_length = strlen(target_file);
  const size_t sanitized_target_file_length = (target_file[target_file_length - 1] == fsm->dir_sep) ? target_file_length - 1 : target_file_length;

  const struct fs_str sanitized_target_file = { target_file, sanitized_target_file_length };

  struct fs_inode inode;
  assert_user(fsm, get_inode(fsm, &sanitized_target_file, &inode), 123, "Target not found");

  inode.oid = owner_fields->pw_uid;
  inode.gid = group_fields->gr_gid;

  write_inode(fsm, &inode);
}


void fs_lnhard (struct fs_meta* const fsm, char* const target_file, char* const link_file) {
  allow_write(fsm);

  const size_t target_file_length = strlen(target_file);
  const size_t sanitized_target_file_length = (target_file[target_file_length - 1] == fsm->dir_sep) ? target_file_length - 1 : target_file_length;

  const struct fs_str sanitized_target_file = { target_file, sanitized_target_file_length };

  struct fs_inode target_inode;
  assert_user(fsm, get_inode(fsm, &sanitized_target_file, &target_inode), 126, "Target file does not exist!");

  const size_t link_file_length = strlen(link_file);
  const size_t sanitized_link_file_length = (link_file[link_file_length - 1] == fsm->dir_sep) ? link_file_length - 1 : link_file_length;

  const struct fs_str sanitized_link_file = { link_file, sanitized_link_file_length };

  const size_t tokens_count = get_tokens_count(&sanitized_link_file, fsm->dir_sep);

  assert(fsm, tokens_count > 1, 127);

  size_t* const tokens_offsets = fs_malloc(fsm, tokens_count * sizeof(size_t));

  str_split(&sanitized_link_file, tokens_offsets, fsm->dir_sep);

  const size_t link_parent_file_length = tokens_offsets[tokens_count - 1] - 1;

  const struct fs_str link_parent_file = { link_file, link_parent_file_length};

  struct fs_inode link_parent_inode;
  assert_user(fsm, get_inode(fsm, &link_parent_file, &link_parent_inode), 128, "Invalid path for link!");

  const size_t link_file_name_length = sanitized_link_file.length - tokens_offsets[tokens_count - 1];
  const struct fs_str link_file_name = { link_file + tokens_offsets[tokens_count - 1], link_file_name_length };

  dir_add_file(fsm, &link_parent_inode, &link_file_name, target_inode.self_inode_data_block);

  target_inode.hardlinks_count++;

  write_inode(fsm, &target_inode);
}


void run_cmd (const int argc, char * const * const argv) {
  const char * const FS_PATH_ENV_VAR_NAME = "FS_FILE";
  char * const fs_path = getenv(FS_PATH_ENV_VAR_NAME);

  if (fs_path == NULL) {
    exit(131);
  }

  if (argc < 2) {
    exit(1);
  }

  const char* const cmd_name = argv[1];

  if (strcmp(cmd_name, "mkfs") == 0) {
    fs_mkfs(fs_path);

    return;
  }

  struct fs_meta* const fsm = get_fs_meta(fs_path);

  if (strcmp(cmd_name, "fsck") == 0) {
    assert_user(fsm, argc == 2, 1, "fsck command must be called without arguments!");

    fs_fsck(fsm);
  } else if (strcmp(cmd_name, "debug") == 0) {
    assert_user(fsm, argc == 2, 5, "debug command must be called without arguments!");

    fs_debug(fsm);
  } else if (strcmp(cmd_name, "lsobj") == 0) {
    assert_user(fsm, argc == 3, 6, "lsobj command takes exactly one argument! lsobj target");

    fs_lsobj(fsm, argv[2]);
  } else if (strcmp(cmd_name, "lsdir") == 0) {
    assert_user(fsm, argc == 3, 7, "lsdir command takes exactly one argument! lsdir target");

    fs_lsdir(fsm, argv[2]);
  } else if (strcmp(cmd_name, "stat") == 0) {
    assert_user(fsm, argc == 3, 8, "stat command takes exactly one argument! stat target");

    fs_stat(fsm, argv[2]);
  } else if (strcmp(cmd_name, "mkdir") == 0) {
    assert_user(fsm, argc == 3, 9, "mkdir command takes exactly one argument! mkdir target");

    fs_mkdir(fsm, argv[2]);
  } else if (strcmp(cmd_name, "rmdir") == 0) {
    assert_user(fsm, argc == 3, 10, "rmdir command takes exactly one argument! rmdir target");

    fs_rmdir(fsm, argv[2]);
  } else if (strcmp(cmd_name, "cpfile") == 0) {
    assert_user(fsm, argc == 4, 11, "cpfile command takes exactly two arguments! cpfile src dest");

    fs_cpfile(fsm, argv[2], argv[3]);
  } else if (strcmp(cmd_name, "rmfile") == 0) {
    assert_user(fsm, argc == 3, 4, "rmfile command takes exactly one argument! rmfile target");

    fs_rmfile(fsm, argv[2]);
  } else if (strcmp(cmd_name, "chmod") == 0) {
    assert_user(fsm, argc == 4, 113, "chmod command takes exactly two arguments! chmod accessmode target");

    fs_chmod(fsm, argv[2], argv[3]);
  } else if (strcmp(cmd_name, "chown") == 0) {
    assert_user(fsm, argc == 4, 114, "chown command takes exactly two arguments: chown ownername:groupname target");

    fs_chown(fsm, argv[2], argv[3]);
  } else if (strcmp(cmd_name, "lnhard") == 0) {
    assert_user(fsm, argc == 4, 125, "lnhard command takes exactly two arguments: lnhard target linkname");

    fs_lnhard(fsm, argv[2], argv[3]);
  } else {
    assert_user(fsm, 0, 2, "Unknown command!");
  }

  assert(fsm, fsync(fsm->fd) == 0, 3);

  destroy_fs_meta(fsm);
}


int main (const int argc, char * const * const argv) {
  run_cmd(argc, argv);

  return 0;
}

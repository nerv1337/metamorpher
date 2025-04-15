#include <elf.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define MAX_PATH_LEN 1024
#define DEBUG 1 // Set to 1 to enable debug output
// This file does not work all, initially went into the wrong direction when
// trying to write metamorph code. For this to be metamorphic I would need to
// implement a metamorphic engine which is way to complicated so yea I also
// tried to use the help of Clausde in writing some of this, to no avail

typedef struct {
  uint8_t bytes[8];    // instruction bytes
  uint8_t length;      // instruction length
  uint8_t orig_length; // length of instruction being replaced
  int reg_mask; // bitmask of registers that can be safely modified (0 = none)
} instruction_t;

static const instruction_t nop_replacements[] = {
    {{0x66, 0x90}, 2, 1, 0},                  // 2-byte NOP
    {{0x0F, 0x1F, 0x00}, 3, 1, 0},            // 3-byte NOP
    {{0x0F, 0x1F, 0x40, 0x00}, 4, 1, 0},      // 4-byte NOP
    {{0x0F, 0x1F, 0x44, 0x00, 0x00}, 5, 1, 0} // 5-byte NOP
};

// Replacement for 3-byte instructions (mov rax,rax / xchg rax,rax)
static const instruction_t three_byte_replacements[] = {
    {{0x48, 0x89, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00}, 3, 3, 1}, // mov rax,rax
    {{0x48, 0x87, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00}, 3, 3, 1}, // xchg rax,rax
    {{0x48, 0x85, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00}, 3, 3, 1}, // test rax,rax
    {{0x0f, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 3, 3, 0}, // 3-byte NOP
};

int find_text_section(uint8_t *buf, size_t filesize, size_t *start,
                      size_t *end) {
  if (filesize < sizeof(Elf64_Ehdr)) {
    printf("Error: File too small to be a valid ELF binary\n");
    return -1;
  }

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;

  // Validate ELF magic bytes
  if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
      ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
    printf("Error: Not a valid ELF file\n");
    return -1;
  }

  // Get section header table and string table
  Elf64_Shdr *shdrs = (Elf64_Shdr *)(buf + ehdr->e_shoff);
  Elf64_Shdr *sh_strtab = &shdrs[ehdr->e_shstrndx];
  const char *strtab = (const char *)(buf + sh_strtab->sh_offset);

  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (strcmp(strtab + shdrs[i].sh_name, ".text") == 0) {
      *start = shdrs[i].sh_offset;
      *end = *start + shdrs[i].sh_size;

      if (DEBUG) {
        printf("Found .text section at offset: 0x%zx, size: 0x%zx\n", *start,
               shdrs[i].sh_size);
      }
      return 0; // Success
    }
  }

  printf("Error: Could not find .text section\n");
  return -1;
}

// Function to get path of the binary in memory
int get_path(char *path_buf) {
  ssize_t len = readlink("/proc/self/exe", path_buf, MAX_PATH_LEN - 1);
  if (len == -1) {
    perror("Error reading /proc/self/exe");
    return -1;
  }
  path_buf[len] = '\0';
  return 0;
}

// Debug function to print bytes
void print_bytes(const char *desc, uint8_t *bytes, int len) {
  if (!DEBUG)
    return;

  printf("%s: ", desc);
  for (int i = 0; i < len; i++) {
    printf("%02X ", bytes[i]);
  }
  printf("\n");
}

// Improved function to identify valid instruction boundaries
int is_valid_instruction_boundary(uint8_t *buf, size_t pos, size_t filesize) {

  // Look for common instruction prefixes and opcodes
  if (pos + 1 < filesize) {
    if (buf[pos] == 0xE8 || buf[pos] == 0xE9 || buf[pos] == 0xEB ||
        (buf[pos] >= 0x70 && buf[pos] <= 0x7F)) {
      return 0; // Jump or call instruction
    }

    if (pos > 0) {
      // Avoid middle of REX prefix sequences
      if ((buf[pos - 1] >= 0x40 && buf[pos - 1] <= 0x4F) &&
          !((buf[pos] >= 0x50 && buf[pos] <= 0x5F) || // Push/pop instructions
            (buf[pos] >= 0x80 &&
             buf[pos] <= 0x8F) || // Various group instructions
            (buf[pos] == 0x89 || buf[pos] == 0x8B))) { // MOV instructions
        return 0;
      }
    }
  }

  return 1; // Probably valid
}

// Improved function to copy and modify instruction - now with safety checks
static int copy_and_modify_instruction(uint8_t *dest,
                                       const instruction_t *instr,
                                       uint8_t *orig_bytes, int orig_len) {
  // Verify the original instruction matches what we expect to replace
  if (orig_len != instr->orig_length) {
    if (DEBUG)
      printf("Length mismatch: expected %d, got %d\n", instr->orig_length,
             orig_len);
    return -1;
  }

  if (DEBUG) {
    print_bytes("Original", orig_bytes, orig_len);
    print_bytes("Replacing with", instr->bytes, instr->length);
  }

  // Copy the instruction
  if (memcmp(dest, orig_bytes, instr->length) == 0) {
    printf(
        "Warning: Instruction replacement did not change memory at offset!\n");
  }

  // Only modify registers if the instruction allows it
  if (instr->reg_mask) {
    // We'll only use RAX (0) and RCX (1) to be safer
    uint8_t reg = rand() % 2;

    if (dest[0] == 0x48 &&
        (dest[1] == 0x89 || dest[1] == 0x87 || dest[1] == 0x85)) {
      // For MOV/XCHG/TEST instructions
      if (reg == 1) {                      // Use RCX instead of RAX
        dest[2] = (dest[2] & 0xF8) | 0x01; // Change to RCX
        if (DEBUG)
          printf("Modified register to RCX\n");
      }
    }
  }

  // Print the final result
  if (DEBUG) {
    print_bytes("Result", dest, instr->length);
  }

  return 0; // Success
}
// Find the .text section in the binary

// Perform multiple morphing passes to handle sequential dependencies
int multi_pass_morph(uint8_t *buf, size_t filesize, int num_passes) {

  //////////////////////////////////////////////////////
  ///
  ///  This function was not written by me
  ///
  ///  Claude wrote this function, as the binary would
  ///  sometimes not morph after execution, rendering
  ///  it useless
  ///
  ///  Update: Doesnt seem to help either, nvm
  //////////////////////////////////////////////////////

  int total_mods = 0;

  size_t text_start, text_end;
  // Find the code section
  find_text_section(buf, filesize, &text_start, &text_end);

  // Perform multiple passes
  for (int pass = 0; pass < num_passes; pass++) {
    int mod_count = 0;
    int max_mods_per_pass = 200; // Limit per pass

    printf("Starting morphing pass %d of %d\n", pass + 1, num_passes);

    // Look for specific instruction patterns to replace
    for (size_t i = text_start;
         i < text_end - 3 && mod_count < max_mods_per_pass; i++) {
      if (rand() % 10 > 1) {
        continue;
      }

      // Skip if not a valid instruction boundary
      if (!is_valid_instruction_boundary(buf, i, filesize)) {
        continue;
      }

      // Check for "mov rax, rax" (48 89 C0)
      if (i + 2 < filesize && buf[i] == 0x48 && buf[i + 1] == 0x89 &&
          buf[i + 2] == 0xc0) {
        int instr_idx =
            rand() % (sizeof(three_byte_replacements) / sizeof(instruction_t));
        if (copy_and_modify_instruction(&buf[i],
                                        &three_byte_replacements[instr_idx],
                                        &buf[i], 3) == 0) {
          mod_count++;
          i += 2; // Skip ahead past the instruction
        }
      }
      // Check for "xchg rax, rax" (48 87 C0)
      else if (i + 2 < filesize && buf[i] == 0x48 && buf[i + 1] == 0x87 &&
               buf[i + 2] == 0xc0) {
        int instr_idx =
            rand() % (sizeof(three_byte_replacements) / sizeof(instruction_t));
        if (copy_and_modify_instruction(&buf[i],
                                        &three_byte_replacements[instr_idx],
                                        &buf[i], 3) == 0) {
          mod_count++;
          i += 2; // Skip ahead past the instruction
        }
      }
      // Check for "NOP" (90)
      else if (buf[i] == 0x90) {
        // Only replace single-byte NOPs with single-byte or compatible
        // multi-byte NOP
        if (i + 1 < filesize && buf[i + 1] != 0xE8 &&
            buf[i + 1] != 0xE9) { // Avoid modifying before jumps
          if (copy_and_modify_instruction(&buf[i], &nop_replacements[0],
                                          &buf[i], 1) == 0) {
            mod_count++;
          }
        }
      }
    }

    printf("Pass %d: Made %d instruction modifications\n", pass + 1, mod_count);
    total_mods += mod_count;

    if (mod_count < 10) {
      break;
    }
  }

  printf("Total modifications across all passes: %d\n", total_mods);
  return total_mods;
}

// Improved binary modification function
int modify_bin(FILE *fptr, unsigned long filesize) {
  uint8_t *buf = malloc(filesize);
  if (!buf) {
    printf("Memory allocation failed\n");
    return -1;
  }

  rewind(fptr);

  // Read entire file into mem
  size_t total_read = fread(buf, 1, filesize, fptr);
  if (total_read != filesize) {
    printf("Error: Expected %lu bytes, but read %lu bytes\n", filesize,
           total_read);
    free(buf);
    return -1;
  }

  // We need to init the randomness
  srand(time(NULL) ^ getpid());

  // Perform morphing passes
  int result = multi_pass_morph(buf, filesize, 3); // 3 passes

  if (result <= 0) {
    printf("No modifications made\n");
    free(buf);
    return -1;
  }

  // Write back modified binary
  rewind(fptr);
  size_t bytes_written = fwrite(buf, 1, filesize, fptr);
  fflush(fptr);
  fsync(fileno(fptr));
  msync(buf, filesize, MS_SYNC | MS_INVALIDATE);
  free(buf);

  return bytes_written == filesize ? 0 : -1;
}

int main() {
  srand(time(NULL) ^ getpid()); // Seed randomness

  char exec_path[MAX_PATH_LEN];
  if (get_path(exec_path) != 0)
    return -1;

  // Create a randomized filename
  char new_binary_path[] = "./XXXXXX";
  int fd = mkstemp(new_binary_path);
  if (fd == -1) {
    perror("Error creating temp file");
    return -1;
  }

  printf("New binary path: %s\n", new_binary_path);

  // Copy original executable to temp file
  FILE *orig = fopen(exec_path, "rb");
  if (!orig) {
    perror("Error opening original");
    close(fd);
    return -1;
  }

  // determine Filesize
  fseek(orig, 0, SEEK_END);
  long size = ftell(orig);
  rewind(orig);

  char *buffer = malloc(size);
  if (!buffer) {
    fclose(orig);
    close(fd);
    return -1;
  }

  // Read entire file
  size_t total_read = 0, bytes_read = 0;
  while (total_read < size) {
    bytes_read = fread(buffer + total_read, 1, size - total_read, orig);
    if (bytes_read == 0) {
      if (ferror(orig)) {
        perror("Error reading original file");
        free(buffer);
        fclose(orig);
        close(fd);
        return -1;
      }
      break; // EOF
    }
    total_read += bytes_read;
  }
  fclose(orig);

  // Open for writing
  FILE *temp = fdopen(fd, "wb");
  if (!temp) {
    perror("Error opening temp file for writing");
    free(buffer);
    close(fd);
    return -1;
  }

  // Write copy
  size_t bytes_written = fwrite(buffer, 1, size, temp);
  fflush(temp);
  fsync(fileno(temp));

  free(buffer);

  if (bytes_written != size) {
    printf("Error: Expected to write %ld bytes, but wrote %ld bytes\n", size,
           bytes_written);
    fclose(temp);
    return -1;
  }

  fclose(temp);

  // Reopen the file in read/write mode
  temp = fopen(new_binary_path, "r+b");
  if (!temp) {
    perror("Error reopening temp file");
    return -1;
  }

  // Modify the temporary file
  printf("Modifying binary...\n");
  if (modify_bin(temp, size)) {
    fclose(temp);
    printf("Binary modification failed, keeping original\n");
    remove(new_binary_path);
    return -1;
  }

  fclose(temp);

  // Make the file executable
  if (chmod(new_binary_path, 0755) != 0) {
    perror("Error setting executable permissions");
    return -1;
  }

  printf("New morphed binary created at: %s\n", new_binary_path);

  // Unlink/delete the original file so only the modified binary remains
  if (unlink(exec_path) == 0) {
    printf("File %s deleted successfully \n", exec_path);
  } else {
    perror("Error unlinking file\n");
    printf("Error code: %d\n", errno);
  }
  return 0;
}

#include <assert.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nyx/redqueen.h"
// #include "debug.h"
#include "nyx/file_helper.h"


/*
 * Private Helper Functions Declarations
 */

size_t _count_lines_in_file(FILE *fp);

void _parse_addresses_in_file(FILE *fp, size_t num_addrs, uint64_t *addrs);

/*
 * Public Functions
 */

void write_debug_result(char *buf)
{
    int unused __attribute__((unused));
    int fd = open("/tmp/qemu_debug.txt", O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
    assert(fd > 0);
    unused = write(fd, buf, strlen(buf));
    close(fd);
}

void parse_address_file(char *path, size_t *num_addrs, uint64_t **addrs)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        *num_addrs = 0;
        *addrs     = NULL;
        return;
    }

    *num_addrs = _count_lines_in_file(fp);
    if (*num_addrs == 0) {
        *addrs = NULL;
        goto exit_function;
    }

    assert(*num_addrs < 0xffff);
    *addrs = malloc(sizeof(uint64_t) * (*num_addrs));
    _parse_addresses_in_file(fp, *num_addrs, *addrs);

exit_function:
    fclose(fp);
}


int re_fd = 0;
int se_fd = 0;

void write_re_result(char *buf)
{
    int unused __attribute__((unused));
    if (!re_fd)
        re_fd = open(redqueen_workdir.redqueen_results,
                     O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
    unused = write(re_fd, buf, strlen(buf));
}

void fsync_redqueen_files(void)
{
    if (!se_fd) {
        fsync(se_fd);
    }
    if (!re_fd) {
        fsync(re_fd);
    }
}

void write_se_result(char *buf)
{
    // int fd;
    int unused __attribute__((unused));
    if (!se_fd)
        se_fd = open(redqueen_workdir.symbolic_results,
                     O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
    unused = write(se_fd, buf, strlen(buf));
    // close(fd);
}

void delete_redqueen_files(void)
{
    int unused __attribute__((unused));
    if (!re_fd)
        re_fd = open(redqueen_workdir.redqueen_results,
                     O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
    if (!se_fd)
        se_fd = open(redqueen_workdir.symbolic_results,
                     O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
    unused = ftruncate(re_fd, 0);
    unused = ftruncate(se_fd, 0);
}

/*
 * Private Helper Functions Definitions
 */

size_t _count_lines_in_file(FILE *fp)
{
    size_t val   = 0;
    size_t count = 0;
    while (1) {
        int scanres = fscanf(fp, "%lx", &val);
        if (scanres == 0) {
            printf("WARNING, invalid line in address file");
            assert(scanres != 0);
        }
        if (scanres == -1) {
            break;
        }
        count += 1;
    }
    rewind(fp);
    return count;
}

void _parse_addresses_in_file(FILE *fp, size_t num_addrs, uint64_t *addrs)
{
    for (size_t i = 0; i < num_addrs; i++) {
        assert(fscanf(fp, "%lx", &addrs[i]) == 1);
    }
}

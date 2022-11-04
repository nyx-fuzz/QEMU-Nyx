#include "qemu/osdep.h"

#include <assert.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "nyx/debug.h"
#include "sharedir.h"

// #define SHAREDIR_DEBUG

sharedir_t *sharedir_new(void)
{
    sharedir_t *self        = malloc(sizeof(sharedir_t));
    self->dir               = NULL;
    self->lookup            = kh_init(SHAREDIR_LOOKUP);
    self->last_file_f       = NULL;
    self->last_file_obj_ptr = NULL;
    return self;
}

void sharedir_set_dir(sharedir_t *self, const char *dir)
{
    assert(!self->dir);
    assert(asprintf(&self->dir, "%s", dir) != -1);
}

static bool file_exits(const char *file)
{
    struct stat sb;
    return (stat(file, &sb) == 0);
}

static time_t get_file_mod_time(char *file)
{
    struct stat attr;
    stat(file, &attr);
    return attr.st_mtime;
}

static size_t get_file_size(const char *file)
{
    struct stat st;
    stat(file, &st);
    return st.st_size;
}

static char *sharedir_scan(sharedir_t *self, const char *file)
{
    /*
     * Agent is not under our control, but lets roughly constrain
     * it to anything stored in or linked from sharedir
     */
    if (0 != chdir(self->dir)) {
        nyx_error("Failed to chdir to sharedir: %s", strerror(errno));
        return NULL;
    }

    char *real_path = realpath(file, NULL);
    if (file[0] != '/' && !strstr(file, "/../") && real_path && file_exits(real_path))
    {
        return real_path;
    }

    free(real_path);
    return NULL;
}

static sharedir_file_t *sharedir_get_object(sharedir_t *self, const char *file)
{
    khiter_t         k;
    int              ret;
    sharedir_file_t *obj = NULL;

    k = kh_get(SHAREDIR_LOOKUP, self->lookup, file);

    if (k != kh_end(self->lookup)) {
        /* file already exists in our hash map */
        obj = kh_value(self->lookup, k);

        /* check if file still exists */
        assert(file_exits(obj->path));

        /* check if mod time matches */
        assert(get_file_mod_time(obj->path) == obj->mod_time);

        /* check if file size matches */
        assert(get_file_size(obj->path) == obj->size);

        return obj;
    } else {
        /* nope ! */
        char       *realpath = sharedir_scan(self, file);
        struct stat sb;
        if (realpath != NULL) {
            if (stat(realpath, &sb) == 0 && S_ISDIR(sb.st_mode)) {
                return NULL; // is dir
            }
            obj = malloc(sizeof(sharedir_file_t));
            memset(obj, 0x0, sizeof(sharedir_file_t));
            assert(asprintf(&obj->file, "%s", basename(realpath)) != -1);
            obj->path       = realpath;
            obj->size       = get_file_size(obj->path);
            obj->bytes_left = (uint64_t)obj->size;
            obj->mod_time   = get_file_mod_time(obj->path);

            /* put into hash_list */
            char *new_file = NULL;
            assert(asprintf(&new_file, "%s", file) != -1);
            k = kh_put(SHAREDIR_LOOKUP, self->lookup, new_file, &ret);
            kh_value(self->lookup, k) = obj;

            return obj;
        }

        /* file not found */
        return NULL;
    }
}

static FILE *get_file_ptr(sharedir_t *self, sharedir_file_t *obj)
{
    if (obj == self->last_file_obj_ptr && self->last_file_f) {
        return self->last_file_f;
    }

    if (self->last_file_f) {
        fclose(self->last_file_f);
    }

    FILE *f                 = fopen(obj->path, "r");
    self->last_file_f       = f;
    self->last_file_obj_ptr = obj;
    return f;
}

uint64_t sharedir_request_file(sharedir_t *self, const char *file, uint8_t *page_buffer)
{
    if (!self->dir) {
        nyx_error("Guest requests file <%s> but no sharedir configured!\n", file);
        return 0xFFFFFFFFFFFFFFFFUL;
    }

    FILE *f = NULL;

    sharedir_file_t *obj = sharedir_get_object(self, file);
    if (obj != NULL) {
#ifdef SHAREDIR_DEBUG
        nyx_debug("sharedir_get_object->file: %s\n", obj->file);
        nyx_debug("sharedir_get_object->path: %s\n", obj->path);
        nyx_debug("sharedir_get_object->size: %ld\n", obj->size);
        nyx_debug("sharedir_get_object->bytes_left: %ld\n", obj->bytes_left);
#endif
        if (obj->bytes_left >= 0x1000) {
            f = get_file_ptr(self, obj);
            fseek(f, obj->size - obj->bytes_left, SEEK_SET);
            assert(fread(page_buffer, 1, 0x1000, f) == 0x1000);
            obj->bytes_left -= 0x1000;
            return 0x1000;
        } else {
            if (obj->bytes_left != 0) {
                f = get_file_ptr(self, obj);
                fseek(f, obj->size - obj->bytes_left, SEEK_SET);
                assert(fread(page_buffer, 1, obj->bytes_left, f) == obj->bytes_left);

                uint64_t ret_value = obj->bytes_left;
                obj->bytes_left    = 0;

                return ret_value;
            } else {
                obj->bytes_left = (uint_fast64_t)obj->size;
                return 0;
            }
        }
    } else {
        nyx_error("No such file in sharedir: %s\n", file);
        return 0xFFFFFFFFFFFFFFFFUL;
    }
}

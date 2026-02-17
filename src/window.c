#include "window.h"
#include "term.h"
#include "io.h"
#include "trie.h"
#include "str.h"
#include "colors.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

window
window_create(size_t w, size_t h)
{
        return (window) {
                .ab   = NULL,
                .abi  = 0,
                .bfrs = dyn_array_empty(bufferp_array),
                .w    = w,
                .h    = h,
        };
}

void
window_add_buffer(window *win,
                  buffer *b,
                  int     make_curr)
{
        dyn_array_append(win->bfrs, b);
        if (make_curr) {
                win->ab  = b;
                win->abi = win->bfrs.len-1;
        }
}

static void
close_buffer(window *win)
{
        dyn_array_rm_at(win->bfrs, win->abi);

        if (win->bfrs.len == 0) {
                win->ab = NULL;
                win->abi = 0;
                return;
        }
        else if (win->abi > 0)
                --win->abi;

        win->ab = win->bfrs.data[win->abi];

        if (win->ab)
                buffer_dump(win->ab);
}

static int
save_buffer(window *win)
{
        if (!buffer_save(win->ab))
                return 0;
}

#define MAX_COMPLETIONS  200
#define DISPLAY_COUNT     8
#define MAX_COMPLETIONS_REQUEST  200
#define MAX_VERTICAL_LINES        8

void
find_file(window *win)
{
        cstr_array   files;
        void        *trie;
        char        *chosen_file = NULL;
        str          inbuf;

        files = lsdir(".");
        trie  = trie_alloc();
        inbuf = str_create();

        for (size_t i = 0; i < files.len; ++i)
                (void)trie_insert(trie, files.data[i]);

        size_t selected_idx = 0;
        size_t offset       = 0;

        while (1) {
                char         ch;
                input_type   ty;
                char       **completions = NULL;
                size_t       total_matches = 0;

                completions = trie_get_completions(trie, str_cstr(&inbuf),
                                                   MAX_COMPLETIONS_REQUEST, &total_matches);

                // Keep indices sane
                if (total_matches == 0) {
                        selected_idx = 0;
                        offset = 0;
                } else {
                        if (selected_idx >= total_matches)
                                selected_idx = total_matches - 1;

                        // for now we only show items from offset
                        if (selected_idx < offset)
                                offset = selected_idx;
                        else if (selected_idx >= offset + MAX_VERTICAL_LINES)
                                offset = selected_idx - MAX_VERTICAL_LINES + 1;

                        size_t max_offset = total_matches > MAX_VERTICAL_LINES
                                ? total_matches - MAX_VERTICAL_LINES : 0;
                        if (offset > max_offset)
                                offset = max_offset;
                }

                gotoxy(0, win->h);
                clear_line(0, win->h);
                printf("Find File [ %s ]", str_cstr(&inbuf));
                if (total_matches > 0)
                        printf("  (%zu/%zu)", selected_idx + 1, total_matches);
                if (total_matches >= MAX_COMPLETIONS_REQUEST)
                        printf("  [more…]");

                gotoxy(0, win->h - 1);
                clear_line(0, win->h - 1);

                if (total_matches == 0) {
                        printf("(no matches)");
                } else {
                        size_t cursor_x = 0;
                        size_t items_shown = 0;
                        const size_t sep_len = strlen("  ");

                        for (size_t i = offset; i < total_matches; ++i) {
                                const char *name     = completions[i] ? completions[i] : "?";
                                size_t      name_len = strlen(name);
                                size_t      added    = name_len;

                                // would this full name fit if we add it?
                                size_t would_be = cursor_x;
                                if (items_shown > 0)
                                        would_be += sep_len;

                                would_be += name_len;

                                if (would_be > win->w) {
                                        // Doesn't fit fully, truncate only this one
                                        size_t remaining = win->w - cursor_x;
                                        if (items_shown > 0)
                                                remaining -= sep_len;

                                        // need at least some chars + ellipsis
                                        if (remaining < 4) {
                                                // not even enough for "a..."
                                                break;
                                        }

                                        size_t display_chars = remaining - 3;  // room for ...
                                        if (display_chars < 1) display_chars = 1;

                                        if (items_shown > 0)
                                                printf("%s", "  ");

                                        if (i == selected_idx)
                                                printf(YELLOW BOLD INVERT);

                                        printf("%.*s%s", (int)display_chars, name, "...");

                                        if (i == selected_idx)
                                                printf(RESET);

                                        cursor_x = win->w;  // line is now full
                                        items_shown++;
                                        break;  // no more after truncated item
                                }

                                // Fits fully; print it
                                if (items_shown > 0)
                                        printf("%s", "  ");

                                if (i == selected_idx)
                                        printf(YELLOW BOLD INVERT);

                                printf("%s", name);

                                if (i == selected_idx)
                                        printf(RESET);

                                cursor_x = would_be;
                                items_shown++;
                        }
                }

                gotoxy(strlen("Find File [ ") + str_len(&inbuf), win->h);
                fflush(stdout);

                ty = get_input(&ch);

                switch (ty) {
                case INPUT_TYPE_NORMAL:
                        if (ENTER(ch)) {
                                if (total_matches > 0 && selected_idx < total_matches)
                                        chosen_file = strdup(completions[selected_idx]);
                                free(completions);
                                goto done;
                        }
                        else if (BACKSPACE(ch)) {
                                if (str_len(&inbuf) > 0) {
                                        str_pop(&inbuf);
                                        selected_idx = 0;
                                        offset = 0;
                                }
                        }
                        else if (isprint(ch) || ch == ' ') {
                                str_append(&inbuf, ch);
                                selected_idx = 0;
                                offset = 0;
                        }
                        break;

                case INPUT_TYPE_CTRL:
                        if (ch == CTRL_N) {
                                if (total_matches > 0 && selected_idx < total_matches - 1)
                                        selected_idx++;
                        } else if (ch == CTRL_P) {
                                if (total_matches > 0 && selected_idx > 0)
                                        selected_idx--;
                        } else if (ch == CTRL_G)
                                goto done;
                        break;

                default:
                        break;
                }

                free(completions);
        }

 done:
        trie_destroy(trie);
        dyn_array_free(files);
        str_destroy(&inbuf);

        if (!chosen_file) {
                buffer_dump(win->ab);
                return;
        }

        assert(!is_dir(chosen_file));

        str fp = str_from(chosen_file);
        buffer *b = buffer_from_file(fp, win);
        free(chosen_file);

        if (!b)
                return;

        window_add_buffer(win, b, 1);
        buffer_dump(win->ab);
}

static int
ctrlx(window *win)
{
        char        ch;
        input_type  ty;

        switch (ty = get_input(&ch)) {
        case INPUT_TYPE_CTRL:
                if (ch == CTRL_S)
                        return save_buffer(win);
                if (ch == CTRL_Q)
                        close_buffer(win);
                if (ch == CTRL_F)
                        find_file(win);
        default: break;
        }

        return 1;
}

void
window_handle(window *win)
{
        assert(win->ab);

        buffer_dump(win->ab);
        gotoxy(win->ab->cx, win->ab->cy);
        fflush(stdout);

        while (1) {
                if (!win->ab)
                        break;

                char        ch;
                input_type  ty;
                buffer_proc bproc;

                ty = get_input(&ch);

                if (ty == INPUT_TYPE_ALT && ch == 'x')
                        assert(0);
                else if (ty == INPUT_TYPE_CTRL && ch == CTRL_X)
                        ctrlx(win);
                else {
                        bproc = buffer_process(win->ab, ty, ch);

                        if (bproc == BP_INSERT)
                                buffer_dump_xy(win->ab);
                        else if (bproc == BP_INSERTNL)
                                buffer_dump(win->ab);
                        else if (bproc == BP_MOV)
                                buffer_dump(win->ab);
                }
        }
}

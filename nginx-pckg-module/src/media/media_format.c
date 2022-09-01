#include "media_format.h"

size_t
media_segment_track_get_total_size(media_segment_track_t* track)
{
    vod_list_part_t* part;
    input_frame_t* cur;
    input_frame_t* last;
    size_t size;

    size = 0;

    part = &track->frames.part;
    cur = part->elts;
    last = cur + part->nelts;

    for (;; cur++)
    {
        if (cur >= last)
        {
            if (part->next == NULL)
            {
                break;
            }

            part = part->next;
            cur = part->elts;
            last = cur + part->nelts;
        }

        size += cur->size;
    }

    return size;
}

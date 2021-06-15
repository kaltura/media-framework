#pragma once

typedef void audio_ack_map_t;

typedef struct {
    uint64_t id;
    uint32_t offset;
} audio_ack_offset_t;

audio_ack_map_t *audio_ack_map_create(uint64_t initialFrameId,const char *name);
void audio_ack_map_destroy(audio_ack_map_t *m);
void audio_ack_map_add_input(audio_ack_map_t *m,uint64_t id,uint32_t samples);
void audio_ack_map_add_output(audio_ack_map_t *m,uint32_t samples,bool updateOnly);
void audio_ack_map_ack(audio_ack_map_t *m,uint64_t ack,audio_ack_offset_t *ao);
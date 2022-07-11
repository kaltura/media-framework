#include "mp4_dash_encrypt.h"
#include "mp4_cenc_encrypt.h"
#include "mp4_write_stream.h"
#include "mp4_defs.h"


static u_char mp4_dash_encrypt_clear_key_id[] = {
    0x10, 0x77, 0xef, 0xec, 0xc0, 0xb2, 0x4d, 0x02,
    0xac, 0xe3, 0x3c, 0x1e, 0x52, 0xe2, 0xfb, 0x4b
};


////// video fragment functions

static u_char*
mp4_dash_encrypt_video_write_encryption_atoms(void* context, u_char* p, size_t mdat_atom_start)
{
    mp4_cenc_encrypt_video_state_t* state = (mp4_cenc_encrypt_video_state_t*)context;
    size_t senc_data_size = state->auxiliary_data.pos - state->auxiliary_data.start;
    size_t senc_atom_size = ATOM_HEADER_SIZE + sizeof(senc_atom_t) + senc_data_size;

    // saiz / saio
    p = mp4_cenc_encrypt_video_write_saiz_saio(state, p, mdat_atom_start - senc_data_size);

    // senc
    write_atom_header(p, senc_atom_size, 's', 'e', 'n', 'c');
    write_be32(p, 0x2);        // flags
    write_be32(p, state->base.track->frame_count);
    p = vod_copy(p, state->auxiliary_data.start, senc_data_size);

    return p;
}


static vod_status_t
mp4_dash_encrypt_video_build_fragment_header(
    mp4_cenc_encrypt_video_state_t* state,
    vod_str_t* fragment_header,
    size_t* total_fragment_size)
{
    mp4_muxer_header_extensions_t header_extensions;

    // get the header extensions
    vod_memzero(&header_extensions, sizeof(header_extensions));

    header_extensions.extra_traf_atoms_size =
        state->base.saiz_atom_size +
        state->base.saio_atom_size +
        ATOM_HEADER_SIZE + sizeof(senc_atom_t) + state->auxiliary_data.pos - state->auxiliary_data.start;
    header_extensions.write_extra_traf_atoms_callback = mp4_dash_encrypt_video_write_encryption_atoms;
    header_extensions.write_extra_traf_atoms_context = state;

    mp4_muxer_reset(state->build_fragment_header_ctx);

    // build the fragment header
    return mp4_muxer_build_fragment_header(
        state->base.request_context,
        state->build_fragment_header_ctx,
        0,
        &header_extensions,
        FALSE,
        fragment_header,
        total_fragment_size);
}


////// audio fragment functions

static u_char*
mp4_dash_encrypt_audio_write_encryption_atoms(void* context, u_char* p, size_t mdat_atom_start)
{
    mp4_cenc_encrypt_state_t* state = (mp4_cenc_encrypt_state_t*)context;
    size_t senc_data_size = MP4_AES_CTR_IV_SIZE * state->track->frame_count;
    size_t senc_atom_size = ATOM_HEADER_SIZE + sizeof(senc_atom_t) + senc_data_size;

    // saiz / saio
    p = mp4_cenc_encrypt_audio_write_saiz_saio(state, p, mdat_atom_start - senc_data_size);

    // senc
    write_atom_header(p, senc_atom_size, 's', 'e', 'n', 'c');
    write_be32(p, 0x0);        // flags
    write_be32(p, state->track->frame_count);
    p = mp4_cenc_encrypt_audio_write_auxiliary_data(state, p);

    return p;
}


static vod_status_t
mp4_dash_encrypt_audio_build_fragment_header(
    mp4_cenc_encrypt_state_t* state,
    mp4_muxer_state_t* muxer_state,
    bool_t size_only,
    vod_str_t* fragment_header,
    size_t* total_fragment_size)
{
    mp4_muxer_header_extensions_t header_extensions;
    vod_status_t rc;

    // get the header extensions
    vod_memzero(&header_extensions, sizeof(header_extensions));

    header_extensions.extra_traf_atoms_size =
        state->saiz_atom_size +
        state->saio_atom_size +
        ATOM_HEADER_SIZE + sizeof(senc_atom_t) + MP4_AES_CTR_IV_SIZE * state->track->frame_count;
    header_extensions.write_extra_traf_atoms_callback = mp4_dash_encrypt_audio_write_encryption_atoms;
    header_extensions.write_extra_traf_atoms_context = state;

    // build the fragment header
    rc = mp4_muxer_build_fragment_header(
        state->request_context,
        muxer_state,
        0,
        &header_extensions,
        size_only,
        fragment_header,
        total_fragment_size);
    if (rc != VOD_OK)
    {
        vod_log_debug1(VOD_LOG_DEBUG_LEVEL, state->request_context->log, 0,
            "mp4_dash_encrypt_audio_build_fragment_header: dash_packager_build_fragment_header failed %i", rc);
        return rc;
    }

    mp4_muxer_reset(muxer_state);

    return VOD_OK;
}


////// common functions

vod_status_t
mp4_dash_encrypt_get_fragment_writer(
    segment_writer_t* segment_writer,
    request_context_t* request_context,
    media_segment_t* segment,
    bool_t single_nalu_per_frame,
    bool_t size_only,
    vod_str_t* fragment_header,
    size_t* total_fragment_size,
    mp4_muxer_state_t** processor_state)
{
    mp4_muxer_state_t* state;
    segment_writer_t enc_writer;
    vod_status_t rc;
    uint32_t media_type;

    rc = mp4_muxer_init_state(
        request_context,
        segment,
        TRUE,       // reuse_buffers
        &state);
    if (rc != VOD_OK)
    {
        vod_log_debug1(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_dash_encrypt_get_fragment_writer: mp4_muxer_init_state failed %i", rc);
        return rc;
    }

    enc_writer = *segment_writer;        // must not change segment_writer, otherwise the header will be encrypted
    media_type = segment->tracks[0].media_info->media_type;
    switch (media_type)
    {
    case MEDIA_TYPE_VIDEO:
        rc = mp4_cenc_encrypt_video_get_fragment_writer(
            &enc_writer,
            request_context,
            segment,
            single_nalu_per_frame,
            mp4_dash_encrypt_video_build_fragment_header,
            state,
            fragment_header,
            total_fragment_size);
        if (rc != VOD_OK)
        {
            return rc;
        }

        break;

    case MEDIA_TYPE_AUDIO:
        rc = mp4_cenc_encrypt_audio_get_fragment_writer(
            &enc_writer,
            request_context,
            segment);
        if (rc != VOD_OK)
        {
            return rc;
        }

        rc = mp4_dash_encrypt_audio_build_fragment_header(
            enc_writer.context,
            state,
            size_only,
            fragment_header,
            total_fragment_size);
        if (rc != VOD_OK)
        {
            return rc;
        }

        break;

    default:
        vod_log_error(VOD_LOG_ERR, request_context->log, 0,
            "mp4_dash_encrypt_get_fragment_writer: invalid media type %uD", media_type);
        return VOD_UNEXPECTED;
    }

    return mp4_muxer_start(state, &enc_writer, FALSE, processor_state);
}


static u_char*
mp4_dash_encrypt_write_pssh_header(u_char* p, u_char* id, size_t data_len)
{
    size_t pssh_atom_size;
    int version;

    version = vod_memcmp(id, mp4_dash_encrypt_clear_key_id, sizeof(mp4_dash_encrypt_clear_key_id)) == 0;

    pssh_atom_size = ATOM_HEADER_SIZE + sizeof(pssh_atom_t) + data_len;
    if (version != 0)
    {
        pssh_atom_size -= sizeof(uint32_t);
    }

    write_atom_header(p, pssh_atom_size, 'p', 's', 's', 'h');
    write_be32(p, version << 24);                // version + flags

    p = vod_copy(p, id, VOD_ENC_SYS_ID_SIZE);    // system id
    if (version == 0)
    {
        write_be32(p, data_len);                 // data size
    }
    return p;
}

size_t
mp4_dash_encrypt_base64_pssh_get_size(media_enc_sys_t* sys)
{
    return vod_base64_encoded_length(
        ATOM_HEADER_SIZE + sizeof(pssh_atom_t) + sys->data.len);
}

u_char*
mp4_dash_encrypt_base64_pssh_write(u_char* p, media_enc_sys_t* sys)
{
    u_char pssh_header[ATOM_HEADER_SIZE + sizeof(pssh_atom_t) + 2];
    vod_str_t data;
    vod_str_t pssh;
    vod_str_t base64;
    u_char* ph;
    size_t copy;

    data = sys->data;

    pssh.data = pssh_header;
    ph = mp4_dash_encrypt_write_pssh_header(pssh.data, sys->id, sys->data.len);
    pssh.len = ph - pssh.data;

    if (pssh.len % 3)
    {
        /* copy a few bytes to make sure the header is written without padding */
        copy = 3 - pssh.len % 3;
        if (copy > data.len)
        {
            copy = data.len;
        }

        vod_memcpy(ph, data.data, copy);
        pssh.len += copy;

        data.data += copy;
        data.len -= copy;
    }

    base64.data = p;
    vod_encode_base64(&base64, &pssh);
    p += base64.len;

    base64.data = p;
    vod_encode_base64(&base64, &data);
    p += base64.len;

    return p;
}

size_t
mp4_dash_encrypt_base64_psshs_get_size(media_enc_t* enc)
{
    media_enc_sys_t* elts;
    vod_uint_t i, n;
    size_t size = 0;

    elts = enc->systems.elts;
    n = enc->systems.nelts;

    for (i = 0; i < n; i++)
    {
        size += mp4_dash_encrypt_base64_pssh_get_size(&elts[i]);
    }

    return size;
}

u_char*
mp4_dash_encrypt_base64_psshs_write(u_char* p, media_enc_t* enc)
{
    media_enc_sys_t* elts;
    vod_uint_t i, n;

    elts = enc->systems.elts;
    n = enc->systems.nelts;

    for (i = 0; i < n; i++)
    {
        p = mp4_dash_encrypt_base64_pssh_write(p, &elts[i]);
    }

    return p;
}

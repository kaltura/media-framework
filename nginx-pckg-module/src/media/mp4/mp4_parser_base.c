#include "mp4_parser_base.h"
#include "../read_stream.h"

vod_status_t
mp4_parser_parse_atoms(
    request_context_t* request_context,
    u_char* buf,
    uint64_t size,
    mp4_parse_callback_t callback,
    void* data)
{
    vod_status_t rc;
    mp4_atom_t atom;
    uint64_t atom_size;

    while (size >= ATOM_HEADER_SIZE)
    {
        read_be32(buf, atom_size);
        read_le32(buf, atom.name);
        size -= ATOM_HEADER_SIZE;

        vod_log_debug3(VOD_LOG_DEBUG_LEVEL, request_context->log, 0,
            "mp4_parser_parse_atoms: atom name=%*s, size=%uL", (size_t)sizeof(atom.name), (char*)&atom.name, atom_size);

        switch (atom_size)
        {
        case 1:
            // atom_size == 1 => atom uses 64 bit size
            if (size < sizeof(uint64_t))
            {
                vod_log_error(VOD_LOG_ERR, request_context->log, 0,
                    "mp4_parser_parse_atoms: atom size is 1 but there is not enough room for the 64 bit size");
                return VOD_BAD_DATA;
            }

            atom.header_size = ATOM_HEADER64_SIZE;

            read_be64(buf, atom_size);
            size -= sizeof(uint64_t);
            break;

        case 0:
            // atom_size == 0 => atom extends till the end of the buffer
            atom_size = size + ATOM_HEADER_SIZE;

            // fall through

        default:
            atom.header_size = ATOM_HEADER_SIZE;
        }

        if (atom_size < atom.header_size)
        {
            vod_log_error(VOD_LOG_ERR, request_context->log, 0,
                "mp4_parser_parse_atoms: atom size %uL is less than the atom header size %uD", atom_size, (uint32_t)atom.header_size);
            return VOD_BAD_DATA;
        }

        atom_size -= atom.header_size;
        if (size < atom_size)
        {
            vod_log_error(VOD_LOG_ERR, request_context->log, 0,
                "mp4_parser_parse_atoms: atom size %uL overflows the input stream size %uL", atom_size, size);
            return VOD_BAD_DATA;
        }

        atom.ptr = buf;
        atom.size = atom_size;

        rc = callback(data, &atom);
        if (rc != VOD_OK)
        {
            return rc;
        }

        buf += atom_size;
        size -= atom_size;
    }

    return VOD_OK;
}

vod_status_t
mp4_parser_get_atoms_callback(void* data, mp4_atom_t* atom)
{
    mp4_get_atoms_ctx_t* ctx = data;
    mp4_get_atoms_ctx_t child_ctx;
    mp4_get_atom_t* cur;
    vod_status_t rc;
    mp4_atom_t* atomp;
    u_char* p;

    for (cur = ctx->atoms; cur->atom_name != ATOM_NAME_NULL; cur++)
    {
        if (cur->atom_name != atom->name)
        {
            continue;
        }

        if (cur->children == NULL)
        {
            p = (u_char*)ctx->result;
            atomp = (mp4_atom_t*)(p + cur->target_offset);
            *atomp = *atom;
            break;
        }

        child_ctx.atoms = cur->children;
        child_ctx.result = ctx->result;
        child_ctx.request_context = ctx->request_context;

        rc = mp4_parser_parse_atoms(
            ctx->request_context,
            atom->ptr,
            atom->size,
            &mp4_parser_get_atoms_callback,
            &child_ctx);
        if (rc != VOD_OK)
        {
            return rc;
        }

        break;
    }

    return VOD_OK;
}

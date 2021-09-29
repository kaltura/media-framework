#include <vector>

extern "C"
{
#include "./logger.h"
#include "cc_atsc_a53.h"
}

const std::vector<uint8_t>::size_type MaxCCLength = 96;
struct A53Mapper
{
    std::vector<uint8_t> m_cc;
};

extern "C"
int atsc_a53_handler_create(atsc_a53_handler_t *h)
{
    *h = new A53Mapper();
    return *h ? 0 : AVERROR(ENOMEM);
}

extern "C"
void atsc_a53_handler_free(atsc_a53_handler_t *h)
{
    if(*h)
        delete (A53Mapper*)*h;
    *h = NULL;
}

extern "C"
int atsc_a53_input_frame(atsc_a53_handler_t h,AVFrame *pFrame)
{
   if(!h)
        return AVERROR(EINVAL);
    auto &m = *reinterpret_cast<A53Mapper*>(h);
    const auto sd = av_frame_get_side_data(pFrame,AV_FRAME_DATA_A53_CC);
    if(sd)
    {
        m.m_cc.insert(m.m_cc.end(),sd->data,sd->data + sd->size);
        av_frame_remove_side_data(pFrame,AV_FRAME_DATA_A53_CC);
    }

    return 0;
}

extern "C"
int atsc_a53_output_frame(atsc_a53_handler_t h,AVFrame *pFrame)
{
    if(!h)
        return AVERROR(EINVAL);

    auto &m = *reinterpret_cast<A53Mapper*>(h);
    if(m.m_cc.size())
    {
        const auto sdSize = std::min(m.m_cc.size(),MaxCCLength );
        auto sd = av_frame_new_side_data(pFrame,AV_FRAME_DATA_A53_CC,sdSize);
        if(!sd)
            return AVERROR(ENOMEM);
        std::copy(m.m_cc.begin(),m.m_cc.begin()+sdSize,sd->data);
        m.m_cc.erase(m.m_cc.begin(),m.m_cc.begin() + sdSize);
    }
    return 0;
}
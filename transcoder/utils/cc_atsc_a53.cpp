#include <vector>
#include <unordered_map>

typedef std::vector<uint8_t> cc_fifo_t;
const cc_fifo_t::size_type MaxCCLength = 93;
struct A53Mapper
{
    std::unordered_map<int,cc_fifo_t> m_cc;
};

extern "C"
{
#include "./logger.h"
#include "cc_atsc_a53.h"

    int atsc_a53_handler_create(atsc_a53_handler_t *h)
    {
        *h = new A53Mapper();
        return *h ? 0 : AVERROR(ENOMEM);
    }


    void atsc_a53_handler_free(atsc_a53_handler_t *h)
    {
        if(*h)
            delete (A53Mapper*)*h;
        *h = NULL;
    }

    int atsc_a53_add_stream(atsc_a53_handler_t h,int streamId) {
        if(h)
        {
             LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"atsc_a53_add_stream(%p). stream %d",
                     h,streamId);
              auto &m = *reinterpret_cast<A53Mapper*>(h);
              m.m_cc.insert(std::make_pair(streamId,cc_fifo_t()));
              if(m.m_cc.find(-1) == m.m_cc.end())
                m.m_cc.insert(std::make_pair(-1,cc_fifo_t()));
        }
        return 0;
    }


    int atsc_a53_input_frame(atsc_a53_handler_t h,AVFrame *pFrame)
    {
       if(h)
       {
            auto &m = *reinterpret_cast<A53Mapper*>(h);
            const auto sd = av_frame_get_side_data(pFrame,AV_FRAME_DATA_A53_CC);
            if(sd)
            {
                LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"atsc_a53_input_frame(%p). cc %d bytes",
                       h,sd->size);
                for(auto &it: m.m_cc)
                {
                   it.second.insert(it.second.end(),sd->data,sd->data + sd->size);
                }
            }
            av_frame_remove_side_data(pFrame,AV_FRAME_DATA_A53_CC);
            _S(atsc_a53_output_frame(h,-1,pFrame));
        }
        return 0;
    }


    int atsc_a53_output_frame(atsc_a53_handler_t h,int streamId,AVFrame *pFrame)
    {
        if(h)
        {
            auto &m = *reinterpret_cast<A53Mapper*>(h);
            const auto it = m.m_cc.find(streamId);
            if(it == m.m_cc.end()) {
                LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_WARNING,"atsc_a53_output_frame(%p). stream %d not found",
                    h,streamId);
                return AVERROR(EINVAL);
            }
            auto &v = it->second;
            if(v.size())
            {
                av_frame_remove_side_data(pFrame,AV_FRAME_DATA_A53_CC);
                const auto sdSize = std::min(v.size(),MaxCCLength );
                auto sd = av_frame_new_side_data(pFrame,AV_FRAME_DATA_A53_CC,sdSize);
                if(!sd)
                    return AVERROR(ENOMEM);
                LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"atsc_a53_output_frame(%p). stream %d . cc %d bytes. pts %lld",
                    h,streamId, sdSize, pFrame->pts);
                std::copy(v.begin(),v.begin()+sdSize,sd->data);
                v.erase(v.begin(),v.begin() + sdSize);
            }
        }
        return 0;
    }
}
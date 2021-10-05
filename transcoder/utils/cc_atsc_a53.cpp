#include <vector>
#include <unordered_map>
#include <deque>
#include <algorithm>
#include <stdexcept>
#include <memory>

extern "C"
{

const char *CATEGORY_ATSC_A53 = "ATSC_A53";

#include "../KMP/kalturaMediaProtocol.h"
#include <libavcodec/cbs_sei.h>
#include "./logger.h"
#include "cc_atsc_a53.h"


typedef std::vector<uint8_t> CC_Payload;

// utils

// return < 0 in case of failure or number of processed bytes
int ff_alloc_a53_sei_data(const uint8_t *data,size_t side_data_size,
    std::shared_ptr<AVBufferRef> &sei_payload)
 {

     const auto cc_count = ((side_data_size/3) & 0x1f);

     const auto sei_payload_size = cc_count * 3;

     sei_payload.reset(av_buffer_alloc(sei_payload_size + 11),[](auto b){
        av_buffer_unref(&b);
     });

     if (!sei_payload)
         return AVERROR(ENOMEM);

     uint8_t *sei_data = sei_payload->data;

     // country code
     sei_data[0] = 181;
     sei_data[1] = 0;
     sei_data[2] = 49;

     /**
      * 'GA94' is standard in North America for ATSC, but hard coding
      * this style may not be the right thing to do -- other formats
      * do exist. This information is not available in the side_data
      * so we are going with this right now.
      */
     AV_WL32(sei_data + 3, MKTAG('G', 'A', '9', '4'));
     sei_data[7] = 3;
     sei_data[8] = cc_count | 0x40;
     sei_data[9] = 0;

     memcpy(sei_data + 10, data, sei_payload_size);

     sei_data[sei_payload_size+10] = 255;

     return sei_payload_size;
 }

const size_t maxPayloadSize = 0x1f*3;
const auto seiType = SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35;

int addSeiToPacket(void *logid,AVPacket *pPacket,
        CodedBitstreamContext *cbs,
        CodedBitstreamFragment *frag,
        const CC_Payload &payload)
{

   ff_cbs_fragment_reset(frag);
   _S(ff_cbs_read_packet(cbs,frag,pPacket));
   int ret = 1;
   // 1. append new sei messages
   for(decltype(payload.size()) i = 0; i < payload.size()/maxPayloadSize; i++){
       _S(ff_cbs_sei_add_message(cbs,
                frag,
                0,
                seiType,
                nullptr,
                nullptr));
   }
   // 2. fill in appended messages
   const auto desc = ff_cbs_sei_find_type(cbs, seiType);
   if(!desc)
      throw std::invalid_argument("ff_cbs_sei_find_type desc not found");
   SEIRawMessage *walker = nullptr;
   const auto end = payload.data() + payload.size();
   for(auto buf = payload.data();ret > 0 && buf < end;buf += ret) {
        if(ff_cbs_sei_find_message(cbs,
             frag,
             seiType,
             &walker))
             break;
        if(walker->payload)
            continue;
        std::shared_ptr<AVBufferRef> sei;
        _S(ret = ff_alloc_a53_sei_data(buf,end - buf, sei));
        LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"addSeiToPacket(%p). add cc: %d bytes",
                         logid,sei->size);
        _S(ff_cbs_sei_alloc_message_payload(walker,desc));
        SEIRawUserDataRegistered *udr = reinterpret_cast<SEIRawUserDataRegistered*>(walker->payload);
        udr->data_ref = av_buffer_ref(sei.get());
   }

   _S(ff_cbs_write_packet(cbs,pPacket,frag));

   LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"addSeiToPacket(%p). success",logid);

   return 0;
}

// A53Stream
struct A53Stream {
    typedef int64_t Timestamp;
    struct FrameInfo {
        CC_Payload payload;
        frame_id_t fid;
        Timestamp  pts;
        bool acked;
    };
    typedef std::deque<FrameInfo> Frames;
    Frames m_frames;
    CodedBitstreamContext *m_cbs = nullptr;
    CodedBitstreamFragment m_frag = {0};
    const AVCodecContext *m_codec;
    bool m_bInited = false;
    int init(const AVCodecContext *codec){
        if(m_bInited)
            throw std::invalid_argument("A53Stream already initialized");
        m_codec = codec;
        return 0;
    }
     ~A53Stream()
     {
         if(m_cbs)
             ff_cbs_close(&m_cbs);
         ff_cbs_fragment_free(&m_frag);
     }
    void decoded(AVFrame *pFrame,frame_id_t fid,const AVFrameSideData *sd) {
          if(sd)
          {
             const auto it = std::find_if(m_frames.begin(),m_frames.end(),[&fid] (const auto &s)->bool{
                return fid == s.fid;
             });
             if(it == m_frames.end()) {
                 LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"decoded(%p). fid= %llu pts= %lld cc_size= %d",
                                     this,fid,pFrame->pts,sd->size);
                 m_frames.push_back({{sd->data,sd->data+sd->size},fid,pFrame->pts,false});
             }
          }
    }
    void filtered(AVFrame *pFrame,frame_id_t fid) {
        LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"filtered(%p). fid= %llu pts= %lld",
                     this,fid,pFrame->pts);
        auto itPts = std::find_if(m_frames.begin(),m_frames.end(), [&pFrame] (const auto &s)->bool{
              return s.pts == pFrame->pts;
        });
        if(itPts != m_frames.end()){
            itPts->acked = true;
            auto it = itPts;
            // prepend cc for all unacknowledged frames
            for(;it != m_frames.begin() && !it->acked;--it) {
                  itPts->payload.insert(itPts->payload.begin(),it->payload.begin(),it->payload.end());
            }
            if(!it->acked) {
                LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"filtered(%p). merge range (%lld,%lld) -> (%lld,%lld)",
                  this,it->fid,it->pts,itPts->fid,itPts->pts);
                m_frames.erase(it,itPts);
            }
            if(itPts->payload.size() > 0) {
                const auto sd_size = std::min(maxPayloadSize,itPts->payload.size());
                auto sd = av_frame_new_side_data(pFrame,AV_FRAME_DATA_A53_CC,sd_size);
                if(!sd)
                    throw std::bad_alloc();
                memcpy(sd->data,itPts->payload.data(),sd_size);
                itPts->payload.erase(itPts->payload.begin(),itPts->payload.begin()+sd_size);
                if(itPts->payload.empty()){
                    LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"filtered(%p). erase fid= %lld pts= %lld",
                      this,itPts->fid,itPts->pts);
                    m_frames.erase(itPts);
                }
            }
        }
    }
    int encoded(AVPacket *&pPacket) {
        LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"encoded(%p). encoded: frames %d pts= %lld",
                             this,m_frames.size(),pPacket->pts);
        auto it = std::find_if(m_frames.begin(),m_frames.end(), [&pPacket] (const auto &s)->bool{
            return s.pts == pPacket->pts;
         });
        if(it != m_frames.end()) {
           //ff_cbs_flush(m_cbs);
           if(!m_bInited) {
                m_bInited = true;
                _S(ff_cbs_init(&m_cbs,m_codec->codec_id,nullptr));
                _S(ff_cbs_read_extradata_from_codec(m_cbs,&m_frag,m_codec));
           }
           if(m_cbs) {
             addSeiToPacket(this,pPacket,m_cbs,&m_frag,it->payload);
           }
           m_frames.erase(it);
        } else {
            LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"encoded(%p). missed frame pts= %lld",
                     this,pPacket->pts);
        }
        return 0;
    }
};

struct A53Mapper
{
   std::unordered_map<stream_id_t,std::unique_ptr<A53Stream>> m_cc;
};

int atsc_a53_handler_create(atsc_a53_handler_t *h)
{
    *h = nullptr;
    auto m = new A53Mapper();
    if(!m)
        return AVERROR(ENOMEM);
    *h = m;
    return 0;
}
void atsc_a53_handler_free(atsc_a53_handler_t *h)
{
    if(*h)
        delete (A53Mapper*)*h;
    *h = nullptr;
}
int atsc_a53_add_stream(atsc_a53_handler_t h,AVCodecContext *codec,stream_id_t streamId) {
    if(h)
    {
         LOGGER(CATEGORY_ATSC_A53,AV_LOG_INFO,"atsc_a53_add_stream(%p). stream %d",
                 h,streamId);
          auto &m = *reinterpret_cast<A53Mapper*>(h);
          std::unique_ptr<A53Stream> ptr(new A53Stream());
          if(!ptr.get())
            throw std::bad_alloc();
          _S(ptr->init(codec));
          m.m_cc.insert(std::make_pair(streamId,std::move(ptr)));
    }
    return 0;
}
int atsc_a53_decoded(atsc_a53_handler_t h,AVFrame *f)
{
    LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"atsc_a53_decoded(%p). %p",
               h,f);
    if(h && f)
   {
       const auto sd = av_frame_get_side_data(f,AV_FRAME_DATA_A53_CC);
       if(sd)  {
           frame_id_t fid = AV_NOPTS_VALUE;
           //best effort
           get_frame_id(f,&fid);
            auto &m = *reinterpret_cast<A53Mapper*>(h);
            try {
                for(auto &it: m.m_cc) {
                  it.second->decoded(f,fid,sd);
                }
            } catch (std::exception &e) {
                 LOGGER(CATEGORY_ATSC_A53,AV_LOG_WARNING,"atsc_a53_decoded(%p).error %s",
                      h,e.what());
                 return -1;
            }
            av_frame_remove_side_data(f,AV_FRAME_DATA_A53_CC);
        }
   }
   return 0;
}
int atsc_a53_filtered(atsc_a53_handler_t h,stream_id_t streamId,AVFrame *f)
{
     LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"atsc_a53_filtered(%p). %p",
                   h,f);
      if(h && f)
      {
           frame_id_t fid = AV_NOPTS_VALUE;
           //best effort
           get_frame_id(f,&fid);
           auto &m = *reinterpret_cast<A53Mapper*>(h);
           try {
              auto it = m.m_cc.find(streamId);
              if(it == m.m_cc.end())
                 throw std::out_of_range("streamId out of range");
              it->second->filtered(f,fid);
           } catch (std::exception &e) {
                LOGGER(CATEGORY_ATSC_A53,AV_LOG_WARNING,"atsc_a53_filtered(%p).error %s",
                     h,e.what());
                return -1;
           }
      }
      return 0;
}
int atsc_a53_encoded(atsc_a53_handler_t h,stream_id_t streamId,AVPacket **ppPacket)
{
     LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"atsc_a53_encoded(%p). stream %d %p",
                    h,streamId,ppPacket);
      if(h && ppPacket && *ppPacket)
     {
          auto &m = *reinterpret_cast<A53Mapper*>(h);
          try {
               auto it = m.m_cc.find(streamId);
               if(it == m.m_cc.end())
                  throw std::out_of_range("streamId out of range");
               it->second->encoded(*ppPacket);
          } catch (std::exception &e) {
               LOGGER(CATEGORY_ATSC_A53,AV_LOG_WARNING,"atsc_a53_encoded(%p).error %s",
                    h,e.what());
               return -1;
          }
     }
     return 0;
}
}
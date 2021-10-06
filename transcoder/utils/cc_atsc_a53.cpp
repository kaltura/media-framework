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

#define _L(expr) \
{\
    auto __ret = expr;\
    if(__ret < 0) \
    {\
         LOGGER(CATEGORY_ATSC_A53,AV_LOG_ERROR,"%s(%d) " #expr " failed with error= %d .errno= %d", __FUNCTION__, __LINE__,__ret,errno); \
         return __ret; \
    } \
}

typedef std::vector<uint8_t> CC_Payload;

// utils

// return < 0 in case of failure or number of processed bytes
static int ff_alloc_a53_sei_data(const uint8_t *data,size_t size,
    std::shared_ptr<AVBufferRef> &sei_payload)
 {

     const auto cc_count = ((size/3) & 0x1f);

     const auto sei_payload_size = cc_count * 3;

     sei_payload.reset(av_buffer_alloc(sei_payload_size + 10),[](auto b){
        av_buffer_unref(&b);
     });

     if (!sei_payload)
         return AVERROR(ENOMEM);

     uint8_t *sei_data = sei_payload->data;

     // country code
     // *sei_data++ = 181;
     *sei_data++ = 0;
     *sei_data++ = 49;

     /**
      * 'GA94' is standard in North America for ATSC, but hard coding
      * this style may not be the right thing to do -- other formats
      * do exist. This information is not available in the side_data
      * so we are going with this right now.
      */
     AV_WL32(sei_data, MKTAG('G', 'A', '9', '4'));
     sei_data += 4;
     *sei_data++ = 3;
     *sei_data++ = cc_count | 0x40;
     *sei_data++ = 0;

     memcpy(sei_data, data, sei_payload_size);
     sei_data += sei_payload_size;
     *sei_data++ = 255;

     return sei_payload_size;
 }

const size_t maxPayloadSize = 0x1f*3;
const auto seiType = SEI_TYPE_USER_DATA_REGISTERED_ITU_T_T35;

static int addSeiToPacket(void *logid,AVPacket *pPacket,
        CodedBitstreamContext *cbs,
        CodedBitstreamFragment *frag,
        const CC_Payload &payload)
{
   //sanity check
   if(!(pPacket && frag && cbs && !payload.empty())){
      LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"addSeiToPacket(%p). validation failed",logid);
      return 0;
   }
   ff_cbs_fragment_reset(frag);
   _L(ff_cbs_read_packet(cbs,frag,pPacket));
   // append sei messages
   const auto desc = ff_cbs_sei_find_type(cbs, seiType);
   if(!desc)
      throw std::invalid_argument("ff_cbs_sei_find_type desc not found");
   const auto end = payload.data() + payload.size();
   int ret = 1;
   for(auto buf = payload.data();ret > 0 && buf < end;buf += ret) {
         _L(ff_cbs_sei_add_message(cbs,frag,desc->prefix,seiType,nullptr,nullptr));
          SEIRawMessage *message = nullptr;
         _L(ff_cbs_sei_find_message(cbs,frag,seiType,&message));
         while(message->payload)
            message++;
        std::shared_ptr<AVBufferRef> sei;
        _L(ret = ff_alloc_a53_sei_data(buf,end - buf, sei));
        LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"addSeiToPacket(%p). add sei: %d bytes",
                         logid,sei->size);
        _L(ff_cbs_sei_alloc_message_payload(message,desc));
        SEIRawUserDataRegistered *udr = reinterpret_cast<SEIRawUserDataRegistered*>(message->payload);
        udr->data_ref = av_buffer_ref(sei.get());
        udr->data = udr->data_ref->data;
        udr->data_length = udr->data_ref->size;
        udr->itu_t_t35_country_code = 0xb5;
   }
   _L(ff_cbs_write_packet(cbs,pPacket,frag));
   LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"addSeiToPacket(%p). updated packet",logid);
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
    typedef Frames::iterator Fiter;
    CodedBitstreamContext *m_cbs = nullptr;
    CodedBitstreamFragment m_frag = {0};
    const AVCodecContext *m_codec;
    bool m_bInited = false;
    void init(const AVCodecContext *codec){
        if(m_bInited)
            throw std::invalid_argument("A53Stream already initialized");
        m_codec = codec;
    }
    ~A53Stream()
    {
        if(m_cbs)
           ff_cbs_close(&m_cbs);
        ff_cbs_fragment_free(&m_frag);
    }
    void decoded(AVFrame *pFrame,frame_id_t fid,const AVFrameSideData *sd) {
         CC_Payload payload;
         if(sd)
             payload.insert(payload.end(),sd->data,sd->data+sd->size);
         m_frames.push_back({payload,fid,pFrame->pts,false});
         LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"decoded(%p). fid= %llu pts= %lld cc_size= %d",
             this,fid,pFrame->pts,sd ? sd->size : 0);
    }

    void filtered(AVFrame *pFrame,frame_id_t fid) {
        LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"filtered(%p). fid= %llu pts= %lld",
                     this,fid,pFrame->pts);
        // find a filtered frame with corresponding fid
        auto itFiltered = std::find_if(m_frames.begin(),m_frames.end(),
            [&fid] (const auto &s)->bool{return s.fid == fid;});
        if(itFiltered != m_frames.end()) {
            LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"filtered(%p). found frame (%lld,%lld)",
                this,itFiltered->fid,itFiltered->pts);
            if(!itFiltered->acked) {
                //remove frames which won't be encoded while preserving cc content
                itFiltered = collapseFrames(itFiltered);
                //try to minimize overhead of parsing+adding sei to encoded frame
                //updateFrame(pFrame,itFiltered);
            }
            // remove frame with no cc in it
            if(itFiltered->payload.empty()) {
                 LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"filtered(%p). fid= %lld pts= %lld empty payload -> erase",
                   this,itFiltered->fid,itFiltered->pts);
                 m_frames.erase(itFiltered);
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
                _L(ff_cbs_init(&m_cbs,m_codec->codec_id,nullptr));
                _L(ff_cbs_read_extradata_from_codec(m_cbs,&m_frag,m_codec));
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
private:
    Fiter collapseFrames(Fiter itFiltered) {
        // if any of preceding frames are being dropped by filter it should be merged with
        // current one.
        auto rit = std::find_if(std::make_reverse_iterator(itFiltered),m_frames.rend(),
                         [](const auto &it)->bool{return it.acked;});
        itFiltered->acked = true;
        auto it = (--rit).base();
        if(it < itFiltered) {
            CC_Payload payload;
            for(auto it1 = it;it1 <= itFiltered;it1++) {
                if(!it1->payload.empty())
                  payload.insert(payload.end(),it1->payload.begin(),it1->payload.end());
            }
            itFiltered->payload = payload;
            LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"filtered(%p). merge range (%lld,%lld) -> (%lld,%lld) payload %d",
                this,it->fid,it->pts,itFiltered->fid,itFiltered->pts,itFiltered->payload.size());
            itFiltered = m_frames.erase(it,itFiltered);
        }
        return itFiltered;
    }
    void updateFrame(auto pFrame,Fiter itFiltered){
         if(!itFiltered->payload.empty()) {
            const auto sd_size = std::min(maxPayloadSize,itFiltered->payload.size());
            auto sd = av_frame_new_side_data(pFrame,AV_FRAME_DATA_A53_CC,sd_size);
            if(!sd)
                throw std::bad_alloc();
            ::memcpy(sd->data,itFiltered->payload.data(),sd_size);
            itFiltered->payload.erase(itFiltered->payload.begin(),itFiltered->payload.begin()+sd_size);
            LOGGER(CATEGORY_ATSC_A53,AV_LOG_DEBUG,"filtered(%p). fid= %lld pts= %lld payload created side data of size %d on filtered frame. payload left %d",
               this,itFiltered->fid,itFiltered->pts,sd_size,itFiltered->payload.size());
        }
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
        try {
             LOGGER(CATEGORY_ATSC_A53,AV_LOG_INFO,"atsc_a53_add_stream(%p). stream %d",
                     h,streamId);
              auto &m = *reinterpret_cast<A53Mapper*>(h);
              std::unique_ptr<A53Stream> ptr(new A53Stream());
              if(!ptr.get())
                throw std::bad_alloc();
              ptr->init(codec);
          m.m_cc.insert(std::make_pair(streamId,std::move(ptr)));
          } catch(std::exception &e){
               LOGGER(CATEGORY_ATSC_A53,AV_LOG_ERROR,"atsc_a53_add_stream(%p). stream %d. error %s",
                      h,streamId,e.what());
             return -1;
          }
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
        if(sd) {
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
#include <vector>
#include <unordered_map>
#include <deque>
#include <algorithm>
#include <stdexcept>
#include <memory>

extern "C"
{
#include "../KMP/kalturaMediaProtocol.h"
#include <libavcodec/cbs_sei.h>
#include "./logger.h"
#include "cc_atsc_a53.h"


typedef std::vector<uint8_t> CC_Payload;
const CC_Payload::size_type MaxCCLength = 93;

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

    int init(enum AVCodecID codecId){
       return ff_cbs_init(&m_cbs,codecId,nullptr);
    }

     ~A53Stream()
     {
         if(m_cbs)
             ff_cbs_close(&m_cbs);
     }

    void decoded(AVFrame *pFrame,frame_id_t fid,const AVFrameSideData *sd) {
          if(sd)
          {
             const auto it = std::find_if(m_frames.begin(),m_frames.end(),[&fid] (const auto &s)->bool{
                return fid == s.fid;
             });
             if(it == m_frames.end()) {
                 m_frames.push_back({{sd->data,sd->data+sd->size},fid,pFrame->pts,false});
             }
          }
    }
    void filtered(AVFrame *pFrame,frame_id_t fid) {
        auto itPts = std::find_if(m_frames.begin(),m_frames.end(), [&pFrame] (const auto &s)->bool{
              return s.pts == pFrame->pts;
        });
        if(itPts != m_frames.end()){
            itPts->acked = true;
            auto it = itPts;
            // append cc for all unacknowledged frames to either end
            for(;it != m_frames.begin() && !it->acked;--it) {
                  itPts->payload.insert(itPts->payload.end(),it->payload.begin(),it->payload.end());
            }
            m_frames.erase(it,itPts);
        }
    }
    void encoded(AVPacket *&pPacket) {
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"encoded(%p). encoded: frames %d",
                             this,m_frames.size());
        auto it = std::find_if(m_frames.begin(),m_frames.end(), [&pPacket] (const auto &s)->bool{
            return s.pts == pPacket->pts;
         });
        if(it != m_frames.end()) {

           // TODO: append cc data in chunks of MaxCCLength
           m_frames.erase(it);
        }
    }
 };

struct A53Mapper
{
    enum AVCodecID m_codecId;
    std::unordered_map<int,std::unique_ptr<A53Stream>> m_cc;
    A53Mapper(enum AVCodecID cid) :m_codecId(cid)
    {}
};


int atsc_a53_handler_create(enum AVCodecID codecId,atsc_a53_handler_t *h)
{
    *h = nullptr;
    auto m = new A53Mapper(codecId);
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
int atsc_a53_add_stream(atsc_a53_handler_t h,int streamId) {
    if(h)
    {
         LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"atsc_a53_add_stream(%p). stream %d",
                 h,streamId);
          auto &m = *reinterpret_cast<A53Mapper*>(h);
          std::unique_ptr<A53Stream> ptr(new A53Stream());
          if(!ptr.get())
            throw std::bad_alloc();
          _S(ptr->init(m.m_codecId));
          m.m_cc.insert(std::make_pair(streamId,std::move(ptr)));
    }
    return 0;
}
int atsc_a53_decoded(atsc_a53_handler_t h,AVFrame *f)
{
    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"atsc_a53_decoded(%p). %p",
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
                 LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_WARNING,"atsc_a53_decoded(%p).error %s",
                      h,e.what());
                 return -1;
            }
            av_frame_remove_side_data(f,AV_FRAME_DATA_A53_CC);
        }
   }
   return 0;
}
int atsc_a53_filtered(atsc_a53_handler_t h,int streamId,AVFrame *f)
{
     LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"atsc_a53_filtered(%p). %p",
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
                LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_WARNING,"atsc_a53_filtered(%p).error %s",
                     h,e.what());
                return -1;
           }
      }
      return 0;
}
int atsc_a53_encoded(atsc_a53_handler_t h,int streamId,AVPacket **ppPacket)
{
     LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"atsc_a53_encoded(%p). stream %d %p",
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
               LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_WARNING,"atsc_a53_encoded(%p).error %s",
                    h,e.what());
               return -1;
          }
     }
     return 0;
}
}
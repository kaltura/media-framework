#include "./ackHandlerInternal.h"
#include <algorithm>

class VideoAckMap : public BaseAckMap {
    typedef uint64_t Timestamp;
    struct FrameDesc {
        frameId_t id;
        uint32_t  offset;
    };
    typedef std::pair<Timestamp,FrameDesc> Frame;
    typedef std::pair<frameId_t,FrameDesc> Mapping;

    std::deque<Frame> m_input;
    std::deque<Mapping> m_output;
    frameId_t           m_lastKeyFrameId;

public:
    VideoAckMap(uint64_t initialFrameId,const char * name)
        :BaseAckMap(name),m_lastKeyFrameId(initialFrameId)
    {}
    void addIn(const ack_desc_t &desc)  throw() {
        // wait for the first key frame to arrive
        FrameDesc fd = {desc.id,0};
        if(desc.key) {
          m_lastKeyFrameId = desc.id;
        } else {
            fd.offset = m_lastKeyFrameId - fd.id;
            fd.id = m_lastKeyFrameId;
        }
        m_input.push_back(std::make_pair(desc.pts,fd));
    }
    void addOut(const ack_desc_t &desc) throw() {
        if(desc.key){
            //ffmpeg encoders do not modify input sample timestamps...
            auto it = std::find_if(m_input.begin(),m_input.end(),[&desc](const auto &f)->bool{
                 return f.first == desc.pts;
            });
            if(it == m_input.end()){
                throw std::out_of_range("didn't find input frame corresponding to output frame");
            }
            m_output.push_back(std::make_pair(desc.id,it->second));
            m_input.erase(m_input.begin(),it);
        }
    }

    void map(const frameId_t &ack,ack_desc_t &ao) throw() {
        auto it = std::find_if(m_output.begin(),m_output.end(),[&ack](const auto &m)->bool{
            return m.first == ack;
        });
        if(it == m_output.end()){
            LOGGER(LoggingCategory,AV_LOG_ERROR,"(%s) video map. map ack %lld -> failed in range %lld-%lld",
                     m_name.c_str(),ack,m_output.front().first,m_output.back().first);
            throw std::out_of_range("ack is out of range");
        }
        if(it->second.offset){
            LOGGER(LoggingCategory,AV_LOG_WARNING,"(%s) video map. mapped ack %lld to non-key frame %lld offset %ld",
                m_name.c_str(), ack, it->second.id, it->second.offset);
        }
        ao.offset = it->second.offset;
        ao.id = it->second.id;
        m_output.erase(m_output.begin(),it);
        LOGGER(LoggingCategory,AV_LOG_INFO,"(%s) video map. map ack %lld -> %lld,%lld",
             m_name.c_str(),ack,ao.id,ao.offset);
     }
};

extern "C"
int video_ack_map_create(uint64_t initialFrameId,uint64_t initialFrameIdOutput,const char *name,ack_handler_t *h) {
    ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
    if(!ahc)
        return AVERROR(EINVAL);
    ahc->ctx = new VideoAckMap(initialFrameId,name);
    if(!ahc->ctx)
        return AVERROR(ENOMEM);
    ahc->destroy = &BaseAckMap::ack_map_destroy;
    h->filtered = &BaseAckMap::ack_map_add_input;
    h->encoded = &BaseAckMap::ack_map_add_output;
    h->map = &BaseAckMap::ack_map_ack;
    return 0;
}

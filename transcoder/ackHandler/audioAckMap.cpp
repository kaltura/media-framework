#include "./ackHandlerInternal.h"
#include <sstream>

typedef int64_t streamOffset_t;


template<typename T,typename C>
struct Repeated {
    T m_val;
    C m_counter;

    typedef Repeated<T,C> RepeatedT;
    typedef T duration;
    typedef C counter;

    explicit Repeated(const T &val,const C& c = 0):m_val(val),m_counter(c)
    {
    }

    Repeated(const Repeated&o):m_val(o.m_val),m_counter(o.m_counter)
    {}

    Repeated&operator=(const Repeated&o){
        const_cast<T&>(m_val) = o.m_val;
        m_counter = o.m_counter;
        return *this;
    }
};
/*
 class FrameHistory:
    handles book keeping for input frames and their stream offsets
    in terms of audio samples
 */
class FrameHistory {
    typedef Repeated<int32_t,int32_t> RepeatedFrame;
    typedef std::deque<RepeatedFrame> Frames;
    typedef Frames::iterator iterator;

    std::deque<RepeatedFrame>  m_q;
    frameId_t m_baseFrame,m_lastFrame;
    streamOffset_t m_streamOffset = 0;
    streamOffset_t m_total = 0; // diagnostics
    std::string m_name;

    void handleFrameDiscontinuity(int c,const RepeatedFrame::duration &dur) {
        if(c < 0){
               if(c == -1){
                   LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. duplicate frame %ld next %ld samples %ld",
                                   m_name.c_str(),m_lastFrame+c,m_lastFrame,dur);
                       auto &r = m_q.back();
                      //special case where frame spans several samples
                      if(r.m_counter>1){
                        r.m_counter--;
                        m_q.push_back(RepeatedFrame(r.m_val+dur,1));
                    } else {
                        m_q.back() = RepeatedFrame(r.m_val+dur,1);
                    }
              } else {
                    LOGGER(LoggingCategory,AV_LOG_ERROR,"(%s) audio map. bad frame %ld < %ld",
                                m_name.c_str(),m_lastFrame+c,last()-1);
                    throw std::out_of_range("bad frame id supplied");
              }
        } else if(c > 1)
           m_q.push_back(RepeatedFrame(0,c-1));
    }

 public:
    FrameHistory(const std::string &name,const frameId_t &id) : m_baseFrame(id),m_lastFrame(id),m_name(name)
    {}

    void addFrame(const frameId_t &fd,const RepeatedFrame::duration &dur) {
        auto c = int(fd - m_lastFrame);
        m_total += dur;
        handleFrameDiscontinuity(c,dur);
        if(m_q.empty() || m_q.back().m_val != dur)
            m_q.push_back(RepeatedFrame(dur));
        m_q.back().m_counter++;
        m_lastFrame += c;
     }
    auto frameByOffset(streamOffset_t off) {
        off -= m_streamOffset;
        auto walker = m_baseFrame;
        for(const auto& r : m_q) {
           if(off <= r.m_counter*r.m_val) {
               const auto c = frameId_t(off / r.m_val);
               walker += c;
               return std::make_pair(walker,off - c * r.m_val);
           }
           off -= r.m_val * r.m_counter;
           walker += r.m_counter;
        }
        throw std::out_of_range("offset out of frame range");
    }
    auto offsetByFrame(frameId_t fd)  {
        if(fd < m_baseFrame || fd > m_lastFrame) {
           std::ostringstream reason;
           reason << "offsetByFrame. frame id " << fd << " is out of range " << m_baseFrame << " - " << m_lastFrame;
           throw std::out_of_range(reason.str().c_str());
        }
        fd -= m_baseFrame;
        auto lo = m_streamOffset, hi = lo;
        for(const auto& r : m_q) {
            if(r.m_counter >= fd) {
                lo += fd * r.m_val;
                hi = lo + r.m_val;
                break;
            }
            lo += r.m_val * r.m_counter;
            fd -= r.m_counter;
        }
        return std::make_pair(lo,hi);
    }
    void removeFrames(const frameId_t &fd)  {
         if(fd < m_baseFrame || fd >= m_lastFrame)
           return;
         while(!m_q.empty()){
            auto &r = m_q.front();
            if(m_baseFrame + r.m_counter - 1 >= fd){
                const auto c = fd - m_baseFrame + 1;
                r.m_counter -= c;
                m_streamOffset += c * r.m_val;
                m_baseFrame = fd + 1;
                break;
            }
            m_baseFrame += r.m_counter;
            m_streamOffset += r.m_counter * r.m_val;
            m_q.pop_front();
         }
         assert(m_baseFrame<=m_lastFrame);
    }
    frameId_t last() const {
        return m_lastFrame;
    }
    frameId_t first() const {
        return m_baseFrame;
    }
    void dump(int level = AV_LOG_DEBUG) {
         if(get_log_level(LoggingCategory)<level)
            return;
         streamOffset_t totalSamples = 0;
         LOGGER(LoggingCategory,level,"(%s) audio map. dump. base frame %lld-%lld  base stream offset %lld",
                   m_name.c_str(),m_baseFrame,m_lastFrame,m_streamOffset);
         for(const auto& r : m_q) {
            LOGGER(LoggingCategory,level,"(%s) audio map. dump. %ld %ld",
                m_name.c_str(),r.m_val,r.m_counter);
                totalSamples += r.m_val*r.m_counter;
         }
         LOGGER(LoggingCategory,level,"(%s) audio map. ~dump. samples since last ack point: %lld total samples: %lld",
            m_name.c_str(),totalSamples, m_total);
    }
    // update sample offset for the last frame
    void adjustLastFrameDuration(RepeatedFrame::duration by) {
        if(!by)    return;
        LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. adjustLastFrameDuration frame %lld %ld samples",
                m_name.c_str(),last(),by);
        auto &last = m_q.back();
        if(last.m_counter == 1) {
            last.m_val += by;
            if(m_q.size() > 1){
                auto &prev = *--(--m_q.end());
                if(prev.m_val == last.m_val){
                    prev.m_counter++;
                    m_q.pop_back();
                }
            }
        } else {
            last.m_counter--;
            m_q.push_back(RepeatedFrame(by,1));
        }
    }
};

/*
    class AudioAckMap.
    responsibilities:
    * maintain history for un-acked input & output audio frames.
    * handle ack and remove acked intervals for both input&output.
    * aligns offsets for output on input to provide for mapping between.
*/
struct AudioAckMap : public BaseAckMap {
  FrameHistory m_in;
  // aux structure to keep last filtered frames. output frames' stream offset
  // is same as those in <m_out> while frame ids match those in <m_in>.
  // correspondence between in & out can be derived from this.
  std::deque<ack_desc_t> m_filtered;
  FrameHistory m_out;

  AudioAckMap(const uint64_t &idIn,const uint64_t &idOut,const std::string &name)
    :BaseAckMap(name),
    m_in(name+".in",idIn),
    m_out(name+".out",idOut)
     {
        LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. c-tor initial ack: input %lld output %lld",
          m_name.c_str(),idIn,idOut);
    }
    ~AudioAckMap() {
      LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. ~d-tor", m_name.c_str());
    }
   auto lastIn() const {
     return m_in.last() - 1;
   }
   auto lastOut() const {
     return m_out.last() - 1;
   }
  // a new frame is fed to encoder
  void addIn(const ack_desc_t &desc)  {
        m_in.addFrame(desc.id,desc.offset);
        LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. add input frame %lld %ld samples",
             m_name.c_str(), desc.id, desc.samples);
  }
  void addFiltered(const ack_desc_t &desc_in) {
      // desc contains input frame id and in/deflated samples
      auto desc = desc_in;
      if(desc.id == INVALID_FRAME_ID)
            desc.id = m_in.last();
      if(m_filtered.empty() || m_filtered.back().id != desc.id)
            m_filtered.push_back(desc);
      else
            m_filtered.back().samples +=  desc.samples;
      LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. add filtered frame %lld %ld samples",
           m_name.c_str(), desc.id, desc.samples);
  }
  // new output frame is produced
  void addOut(const  ack_desc_t &desc)  {
      auto nextFrameId = m_out.last() + 1;

      LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. add output frame %lld %ld samples",
             m_name.c_str(), nextFrameId, desc.samples);
      m_out.addFrame(nextFrameId,desc.samples);

      // single filtered desc can correspond to multiple output frames ot vice versa.
      auto outSamples = desc.samples;
      while(outSamples > 0 && !m_filtered.empty()) {
          // 1. lookup in m_filtered for correct input frame id
          // 2. update desc.samples to reflect actual samples offset.
           auto &filtered = m_filtered.front();
           auto samples = std::min(outSamples,filtered.samples);
           filtered.samples -= samples;
           outSamples -= samples;
           // find sample range corresponding to input frame id
           const auto inOff = m_in.offsetByFrame(filtered.id);
           const auto outOff = m_out.offsetByFrame(m_out.last());
           const auto outputFrameOffset = outOff.first;
           if(outputFrameOffset < inOff.first) {
               // stream is deflated: compensate last out frame
               m_out.adjustLastFrameDuration(inOff.first-outputFrameOffset);
           } else if(outputFrameOffset > inOff.second) {
               // stream is inflated: shorten last out frame
               m_out.adjustLastFrameDuration(inOff.second-outputFrameOffset);
           }
           // filtered frame is not relevant anymore
           if(!filtered.samples) {
               m_filtered.pop_front();
               break;
           }
      }
  }
  // ack is received
  void map(const uint64_t &id,ack_desc_t &ret)  {
       LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. map ack %lld ",
                m_name.c_str(),id);
       ret = {id,0};
       m_in.dump();
       m_out.dump();
       auto off = m_out.offsetByFrame(id);
       LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. map ack %lld off %lld",
            m_name.c_str(),id,off.first);
       auto p = m_in.frameByOffset(off.first);
       // leave mapped frames for book keeping
       m_out.removeFrames(id-1);
       ret.id = p.first;
       ret.offset = p.second;
       m_in.removeFrames(ret.id-1);
       LOGGER(LoggingCategory,AV_LOG_INFO,"(%s) audio map. map ack %lld -> %lld,%lld",
            m_name.c_str(),id,ret.id,ret.offset);
  }
};

extern "C"
int audio_ack_map_create(uint64_t initialFrameId,uint64_t initialFrameIdOutput,const char *name,ack_handler_t *h) {
    ack_handler_ctx_t *ahc = (ack_handler_ctx_t*)h->ctx;
    if(!ahc)
        return AVERROR(EINVAL);
    ahc->ctx = new AudioAckMap(initialFrameId,initialFrameIdOutput,name);
    if(!ahc->ctx)
        return AVERROR(ENOMEM);
    ahc->destroy = &BaseAckMap::ack_map_destroy;
    h->decoded = &BaseAckMap::ack_map_add_input;
    h->filtered = &BaseAckMap::ack_map_add_filtered;
    h->encoded = &BaseAckMap::ack_map_add_output;
    h->map = &BaseAckMap::ack_map_ack;
    return 0;
}

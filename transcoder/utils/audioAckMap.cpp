#include <deque>
#include <string>
#include <cassert>
#include <limits>
extern "C" {
    #include "audioAckMap.h"
    #include "./logger.h"
}

typedef uint64_t frameId_t;
typedef uint64_t streamOffset_t;
const frameId_t InvalidFrameId = 0;
const streamOffset_t InvalidOffset = std::numeric_limits<streamOffset_t>::min();

template<typename T,typename C>
struct Repeated {
    const T m_val;
    C m_counter;
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

class RepeatedFrameId {
    typedef Repeated<uint32_t,uint32_t> RepeatedFrame;
    typedef std::deque<RepeatedFrame> Frames;
    typedef Frames::iterator iterator;

    std::deque<RepeatedFrame>  m_q;
    frameId_t m_baseFrame,m_lastFrame;
    streamOffset_t m_streamOffset = 0;
    streamOffset_t m_total = 0; // diagnostics
 public:
    RepeatedFrameId(const frameId_t &id) : m_baseFrame(id),m_lastFrame(id)
    {}
    void addFrame(const frameId_t &fd,const uint32_t &dur) {
        const auto c = int(fd - m_lastFrame);
        m_total += dur;
        if(c < 0){
               if(c == -1){
                   LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"audio map. duplicate frame %ld samples %ld",
                               fd,dur);
                   auto &r = m_q.back();
                  //special case where frame spans several samples
                  if(r.m_counter>1){
                    r.m_counter--;
                    m_q.push_back(RepeatedFrame(r.m_val+dur,1));
                  } else {
                    m_q.back() = RepeatedFrame(r.m_val+dur,1);
                  }
              } else {
                   LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"audio map. bad frame %ld < %ld",
                              fd,last()-1);
              }
              return;
         }
        if(c > 0)
            m_q.push_back(RepeatedFrame(0,c));
        if(m_q.empty() || m_q.back().m_val != dur)
            m_q.push_back(RepeatedFrame(dur));
        m_q.back().m_counter++;
        m_lastFrame += c + 1;
     }
    auto frameByOffset(streamOffset_t off) {
        off -= m_streamOffset;
        auto walker = m_baseFrame;
        for(const auto& r : m_q) {
           if(off < r.m_counter*r.m_val) {
               const auto c = frameId_t(off / r.m_val);
               walker += c;
               return std::make_pair(walker,off - c * r.m_val);
           }
           off -= r.m_val * r.m_counter;
           walker += r.m_counter;
        }
        return std::make_pair(InvalidFrameId,InvalidOffset);
    }
    auto offsetByFrame(frameId_t fd) {
        if(fd < m_baseFrame || fd >= m_lastFrame)
           return InvalidOffset;
        fd -= m_baseFrame;
        auto off = m_streamOffset;
        for(const auto& r : m_q) {
            if(r.m_counter > fd) {
                off += fd * r.m_val;
                break;
            }
            off += r.m_val * r.m_counter;
            fd -= r.m_counter;
        }
        return off;
    }
    void removeFrames(const frameId_t &fd) {
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
    void dump(const char *extra,int level = AV_LOG_DEBUG) {
         streamOffset_t totalSamples = 0;
         LOGGER(CATEGORY_OUTPUT,level,"(%s) audio map. dump. base frame %lld-%lld  base stream offset %lld",
                   extra,m_baseFrame,m_lastFrame,m_streamOffset);
         for(const auto& r : m_q) {
            LOGGER(CATEGORY_OUTPUT,level,"(%s) audio map. dump. %ld %ld",
                extra,r.m_val,r.m_counter);
                totalSamples += r.m_val*r.m_counter;
         }
         LOGGER(CATEGORY_OUTPUT,level,"(%s) audio map. ~dump. samples since last ack point: %lld total samples: %lld",
            extra,totalSamples, m_total);
    }
};


struct AudioAckMap  {
  // describe encoder buffer: input frames in flight
  RepeatedFrameId m_in;
  RepeatedFrameId m_out;
  const std::string m_name;
  void operator=(AudioAckMap) = delete;
  AudioAckMap(const AudioAckMap&) = delete;
  AudioAckMap(const uint64_t &id,const char *name)
    :m_in(id),
    m_out(id),
    m_name(name) {
        LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. c-tor initial ack %lld ",
          m_name.c_str(),id);
    }
    ~AudioAckMap() {
      LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. ~d-tor", m_name.c_str());
    }
   auto lastIn() const {
     return m_in.last() - 1;
   }
   auto lastOut() const {
     return m_out.last() - 1;
   }
  // a new frame is fed to encoder
  void addIn(const uint64_t &id,uint32_t frameSamples){
        m_in.addFrame(id,frameSamples);
        LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. add input frame %lld %ld samples",
             m_name.c_str(), id, frameSamples);
  }
  // new output frame is produced
  void addOut(uint32_t frameSamples){
      auto nextFrameId = lastOut() + 1;
      LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. add output frame %lld %ld samples",
             m_name.c_str(), nextFrameId, frameSamples);
      m_out.addFrame(nextFrameId,frameSamples);
  }
  // ack is received
  void map(const uint64_t &id,audio_ack_offset_t &ret) {
     LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. map ack %lld ",
            m_name.c_str(),id);
       ret = {id,0};
       m_in.dump("in");
       m_out.dump("out");
       auto off = m_out.offsetByFrame(id);
       if(off == InvalidOffset){
          LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"(%s) audio map. ack %lld failed to get offset",
              m_name.c_str(),id, m_out.first(),m_out.last());
       } else {
           LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. map ack %lld off %lld",
              m_name.c_str(),id,off);
           auto p = m_in.frameByOffset(off);
           m_out.removeFrames(id);
           if(p.first == InvalidFrameId){
               LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"(%s) audio map. ack %lld failed to get input frame id from offset %lld",
                  m_name.c_str(),id,off);
           } else {
              ret.id = p.first;
              ret.offset = p.second;
              m_in.removeFrames(ret.id);
              LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. map ack %lld -> %lld,%lld",
                m_name.c_str(),id,ret.id,ret.offset);
            }
       }
  }
};


void *audio_ack_map_create(uint64_t initialFrameId,const char *name) {
    return new AudioAckMap(initialFrameId,name);
}
void audio_ack_map_destroy(audio_ack_map_t *m) {
    if(m){
        delete reinterpret_cast<AudioAckMap*>(m);
    }
}
void audio_ack_map_add_input(audio_ack_map_t *m,uint64_t id,uint32_t samples) {
   if(m){
       auto &am = *reinterpret_cast<AudioAckMap*>(m);
       am.addIn(id,samples);
   }
}
void audio_ack_map_add_output(audio_ack_map_t *m,uint32_t samples) {
    if(m){
        auto &am = *reinterpret_cast<AudioAckMap*>(m);
        am.addOut(samples);
    }
}

void audio_ack_map_ack(audio_ack_map_t *m,uint64_t ack,audio_ack_offset_t *ao) {
    if(!ao)   return;
    if(m){
        auto &am = *reinterpret_cast<AudioAckMap*>(m);
        am.map(ack,*ao);
    } else {
       ao->id = ack;
       ao->offset = 0;
    }
}

#include "./ackHandlerInternal.h"


typedef uint64_t streamOffset_t;


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
    std::string m_name;

    void handleFrameDiscontinuity(int c,const uint32_t &dur) throw() {
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
    RepeatedFrameId(const std::string &name,const frameId_t &id) : m_baseFrame(id),m_lastFrame(id),m_name(name)
    {}
    void addFrame(const frameId_t &fd,const uint32_t &dur) throw() {
        auto c = int(fd - m_lastFrame);
        m_total += dur;
        handleFrameDiscontinuity(c,dur);
        if(m_q.empty() || m_q.back().m_val != dur)
            m_q.push_back(RepeatedFrame(dur));
        m_q.back().m_counter++;
        m_lastFrame += c;
     }
    auto frameByOffset(streamOffset_t off) throw() {
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
        throw std::out_of_range("offset out of frame range");
    }
    auto offsetByFrame(frameId_t fd) throw() {
        if(fd < m_baseFrame || fd >= m_lastFrame)
           throw std::out_of_range("offset id out of range");
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
};


struct AudioAckMap : public BaseAckMap {
  // describe encoder buffer: input frames in flight
  RepeatedFrameId m_in;
  RepeatedFrameId m_out;

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
  void addIn(const ack_desc_t &desc) throw() {
        m_in.addFrame(desc.id,desc.offset);
        LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. add input frame %lld %ld samples",
             m_name.c_str(), desc.id, desc.samples);
  }
  // new output frame is produced
  void addOut(const  ack_desc_t &desc) throw() {
      auto nextFrameId = m_out.last() + 1;
      LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. add output frame %lld %ld samples",
             m_name.c_str(), nextFrameId, desc.samples);
      m_out.addFrame(nextFrameId,desc.samples);
  }
  // ack is received
  void map(const uint64_t &id,ack_desc_t &ret) throw() {
       LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. map ack %lld ",
                m_name.c_str(),id);
       ret = {id,0};
       m_in.dump();
       m_out.dump();
       auto off = m_out.offsetByFrame(id);
       LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. map ack %lld off %lld",
            m_name.c_str(),id,off);
       auto p = m_in.frameByOffset(off);
       m_out.removeFrames(id);
       ret.id = p.first;
       ret.offset = p.second;
       m_in.removeFrames(ret.id);
       LOGGER(LoggingCategory,AV_LOG_DEBUG,"(%s) audio map. map ack %lld -> %lld,%lld",
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
    h->encoded = &BaseAckMap::ack_map_add_output;
    h->map = &BaseAckMap::ack_map_ack;
    return 0;
}

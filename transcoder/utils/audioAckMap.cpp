#include <deque>
#include <string>
extern "C" {
    #include "audioAckMap.h"
    #include "./logger.h"
}

typedef std::pair<uint32_t,uint32_t> Frame;
typedef std::pair<uint64_t,uint32_t> Mapping;

struct AudioAckMap  {
  // describe encoder buffer: input frames in flight
  std::deque<Frame>  m_qIn;
  uint64_t m_qInBaseFrameId;
  // describe output frames waiting for ack providing mapping between input frame id,
  // offset within input frame and output frame id.
  std::deque<Mapping> m_qOut;
  uint64_t m_qOutBaseFrameId;
  const std::string m_name;
  void operator=(AudioAckMap) = delete;
  AudioAckMap(const AudioAckMap&) = delete;
  AudioAckMap(const uint64_t &id,const char *name)
    :m_qInBaseFrameId(id),
    m_qOutBaseFrameId(id),
    m_name(name) {
        LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"(%s) audio map. c-tor initial ack %lld ",
          m_name.c_str(),id, id);
    }
    ~AudioAckMap() {
      LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"(%s) audio map. ~d-tor", m_name.c_str());
    }
   auto lastIn() const {
     return m_qInBaseFrameId + m_qIn.size() - 1;
   }
   auto lastOut() const {
     return m_qOutBaseFrameId + m_qOut.size() - 1;
   }
  // a new frame is fed to encoder
  void addIn(const uint64_t &id,uint32_t frameSamples){
        while(id > lastIn())
            m_qIn.push_back({0,0});
        m_qIn.push_back(std::make_pair(0,frameSamples));
        LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. add frame %lld %ld samples",
             m_name.c_str(), lastIn(), frameSamples);
  }
  // new output frame is produced
  void addOut(uint32_t samples,bool updateOnly){
        if(!m_qIn.empty()) {
             auto &frame = m_qIn.front();
             if(updateOnly && m_qOut.size()) {
                  LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. update output %lld -> %lld %ld",
                      m_name.c_str(), lastOut(),
                      m_qInBaseFrameId, frame.first);
                 m_qOut.back().second = frame.first;
             } else {
                LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. add output %lld -> %lld %ld",
                        m_name.c_str(),lastOut(),
                         m_qInBaseFrameId, frame.first);
                 m_qOut.push_back(std::make_pair(m_qInBaseFrameId,frame.first));
             }
             while(!m_qIn.empty()){
                auto &frame = m_qIn.front();
                auto left = frame.second - frame.first;
                if(left <= samples) {
                   samples -= left;
                   m_qIn.pop_front();
                   m_qInBaseFrameId++;
                } else {
                   frame.first = samples;
                   break;
                }
            }
        } else {
            LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"(%s) audio map.unexpected add output when encoder queue is empty!",
                m_name.c_str());
        }
  }
  // ack is received
  void map(const uint64_t &id,audio_ack_offset_t &ret) {
       ret = {id,0};
       const auto diff = int64_t(id - m_qOutBaseFrameId);
       if(diff > m_qOut.size()) {
            LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"(%s) audio map. ack %lld > range %lld-%lld",
                 m_name.c_str(),id, m_qOutBaseFrameId, lastOut());
             m_qOutBaseFrameId += m_qOut.size();
             m_qOut.clear();
        } else if(diff < 0) {
           LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. ack %lld < range %lld-%lld",
             m_name.c_str(),id, m_qOutBaseFrameId,lastOut());
        } else {
           const auto &m = *(m_qOut.begin()+diff);
           ret = {m.first,m.second};
           LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. derived ack %lld -> %lld %ld",
               m_name.c_str(),id, ret.id,ret.offset);
           m_qOut.erase(m_qOut.begin(),m_qOut.begin() + diff + 1);
           m_qOutBaseFrameId = id;
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
void audio_ack_map_add_output(audio_ack_map_t *m,uint32_t samples,bool updateOnly) {
    if(m){
        auto &am = *reinterpret_cast<AudioAckMap*>(m);
        am.addOut(samples,updateOnly);
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

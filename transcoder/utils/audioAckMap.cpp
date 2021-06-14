extern "C" {
    #include "audioAckMap.h"
    #include "./logger.h"
}
#include <deque>
#include <string>

typedef std::pair<uint32_t,uint32_t> Frame;
typedef std::pair<uint64_t,uint32_t> Mapping;

struct AudioAckMap  {
  // describe encoder buffer: input frames in flight
  std::queue<Frame>  m_qIn;
  uint64_t m_qInBaseFrameId;
  // describe output frames waiting for ack providing mapping between input frame id,
  // offset within input frame and output frame id.
  std::deque<Mapping> m_qOut;
  uint64_t m_qOutBaseFrameId;
  const std::string m_name;

  void operator=(AudioAckMap) = delete;
  AudioAckMap(const AudioAckMap&) = delete;

  AudioAckMap(const uint64_t &id,const char *name)
    :m_qInBaseFrameId(id-1),
    m_qOutBaseFrameId(id-1),
    m_name(name)
    {}

  // a new frame is fed to encoder
  void addIn(const uint64_t &id,uint32_t frameSamples){
    while(id > m_qInBaseFrameId + m_qIn.size())
        m_qIn.push_back({0});
    m_qIn.push_back(std::make_pair(0,frameSamples));
    LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. add frame %lld %ld samples",
         m_name.c_str(),m_qInBaseFrameId + m_qIn.size(), frameSamples);
  }
  // new output frame is produced
  void addOut(const uint64_t &id,uint32_t samples,bool updateOnly){
    if(!m_qIn.empty()) {
         auto &frame = m_qIn.front();
         if(updateOnly && m_qOut.size) {
              LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. update output %lld -> %lld %ld",
                  m_name.c_str(),m_qOutBaseFrameId + m_qOut.size(),
                  m_qInBaseFrameId + 1, frame.first);
             m_qOut.back().second = frame.first;
         } else {
            LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. add output %lld -> %lld %ld",
                    m_name.c_str(),m_qOutBaseFrameId + m_qOut.size(),
                     m_qInBaseFrameId + 1, frame.first);
             m_qOut.push_back(std::make_pair(m_qInBaseFrameId + 1,frame.first));
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
        LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"(%s) audio map.unexpected add output when encoder queue is empty!");
    }
  }
  // ack is received
  audio_ack_offset_t map(const uint64_t &id) {
       if(id > m_qOutBaseFrameId ){
           if(m_qOutBaseFrameId + m_qOut.size() < id) {
                LOGGER(CATEGORY_OUTPUT,AV_LOG_ERROR,"(%s) audio map.unexpected ack %lld outside range %lld-%lld",
                    id, m_qOutBaseFrameId + 1, m_qOutBaseFrameId + m_qOut.size());
                m_qOutBaseFrameId += m_qOut.size();
                m_qOut.clear();
           } else {
              auto off = id - m_qOutBaseFrameId;
              const auto &m = *(m_qOut.begin()+off);
              audio_ack_offset_t ret = {m.first,m.second};
              LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. ack %lld -> %lld %ld",
                      m_name.c_str(),id, ret.id,ret.offset);
              m_qOut.erase(m_qOut.begin(),m_qOut.begin() + off);
              m_qOutBaseFrameId = id;
              return ret;
           }
       }
       // not found
       LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"(%s) audio map. ack %lld NOT found",
             m_name.c_str(),id);
       return {id,0};
  }
}

extern "C"
{
    audio_ack_map_t *audio_ack_map_create(uint64_t initialFrameId,const char *name) {
        return new AudioAckMap(initialFrameId,name);
    }
    void audio_ack_map_destroy(audio_ack_map_t *m){
        delete m;
    }
    void audio_ack_map_add_input(audio_ack_map_t *m,uint64_t id,uint32_t samples) {
        if(m){
            auto &am = *reinterpret_cast<AudioAckMap*>(m);
            am.addIn(id,samples);
        }
    }
    void audio_ack_map_add_output(audio_ack_map_t *m,uint32_t samples,bool updateOnly)
    {
         if(m){
            auto &am = *reinterpret_cast<AudioAckMap*>(m);
            am.addOut(id,samples,updateOnly);
         }
    }
    audio_ack_offset_t audio_ack_map_ack(audio_ack_map_t *m,uint64_t ack)
    {
        if(m){
           auto &am = *reinterpret_cast<AudioAckMap*>(m);
           return am.map(ack);
        }
        return 0;
    }
}
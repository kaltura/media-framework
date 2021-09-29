CC = gcc -v
CCPP = g++ -v
SRC = $(wildcard *.c)
SRC += $(wildcard ./utils/*.c)
SRC += $(wildcard ./ackHandler/*.c)
SRC += $(wildcard ./common/*.c)
SRC += $(wildcard ./KMP/*.c)
SRC += $(wildcard ./transcode/*.c)
SRC += $(wildcard ./debug/*.c)
DEPS = $(wildcard *.h)
SRC_CPP += $(wildcard ./ackHandler/*.cpp)
SRC_CPP += $(wildcard ./utils/*.cpp)
ODIR=obj
_OBJ = $(SRC:.c=.o)
_OBJ_CPP = $(SRC_CPP:.cpp=.o)
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))
OBJ_CPP = $(patsubst %,$(ODIR)/%,$(_OBJ_CPP))
_EXE = transcoder
EXE = $(patsubst %,$(ODIR)/%,$(_EXE))
OS := $(shell uname)

ifeq ($(OS),Darwin)
        FFMPEG_LIB_DIR := ./ThirdParty/ffmpeg
        X264_LIB_DIR := ./ThirdParty/x264
else
        FFMPEG_LIB_DIR := ./ffmpeg
        X264_LIB_DIR := ./x264
endif

IDIRS = -I. -I$(FFMPEG_LIB_DIR) -I"./common" -I"./utils"  -I"./KMP" -I"./transcode" -I"./debug"
LDIR = -L/usr/local/cuda/lib64 -L$(X264_LIB_DIR) -L$(FFMPEG_LIB_DIR)/libavfilter -L$(FFMPEG_LIB_DIR)/libswresample  -L$(FFMPEG_LIB_DIR)/libswscale -L$(FFMPEG_LIB_DIR)/libwresmple -L$(FFMPEG_LIB_DIR)/libavdevice -L$(FFMPEG_LIB_DIR)/libavutil -L$(FFMPEG_LIB_DIR)/libavformat -L$(FFMPEG_LIB_DIR)/libavcodec -L$(FFMPEG_LIB_DIR)/libpostproc -L/usr/local/lib
FFMPEG_LIBS = -lavfilter  -lavformat -lswscale  -lavcodec   -lavutil  -lswresample -lpostproc -lx264  
LIBS = -lm -lpthread  -lz -lbz2 -ldl 
CUDA_LIBS = -lnppig_static -lnppicc_static -lnppc_static -lnppidei_static -lcublas_static -lcudart_static -lculibos  -lcudart -lstdc++
CFLAGS = -Wall -g $(IDIRS) -fPIC  -static -std=c11 -D_GNU_SOURCE -fexceptions
CPPFLAGS = -Wall -g $(IDIRS) -fPIC  -static -std=c++14 -D_GNU_SOURCE -fexceptions
LDFLAGS =  $(LDIR) $(LIBS)  $(FFMPEG_LIBS) $(LIBS) 


ifeq ($(OS),Darwin)
        LIBS += -liconv  -framework AudioToolbox  -framework VideoToolbox  -framework MediaToolbox  -framework CoreMedia  -framework CoreMediaIO  -framework CoreVideo   -framework CoreAudio  -framework CoreImage  -framework OpenGL   -framework AppKit  -framework QuartzCore  -framework ImageCaptureCore  -framework CoreFoundation  -framework Security   -framework SecurityFoundation  -framework SecurityInterface
else
        LIBS +=  ${CUDA_LIBS} -lrt
endif

dir_guard=@mkdir -p $(@D)

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: %.cpp $(DEPS)
	$(CCPP) -c -o $@ $< $(CPPFLAGS)

$(EXE): $(OBJ) $(OBJ_CPP)
	$(CCPP) -o $@ $^ $(LDFLAGS)

$(phony install): install

install: $(EXE)
	install $(EXE) ./

.PHONY: clean

clean:
	rm -rf $(ODIR) $(ODIR)/common/ $(ODIR)/utils/ $(ODIR)/ackHandler/ $(ODIR)/KMP/ $(ODIR)/transcode/  $(ODIR)/debug/ $(EXE)
	mkdir $(ODIR)
	mkdir $(ODIR)/utils/
	mkdir $(ODIR)/common/
	mkdir $(ODIR)/KMP/
	mkdir $(ODIR)/transcode/
	mkdir $(ODIR)/debug/
	mkdir $(ODIR)/ackHandler/

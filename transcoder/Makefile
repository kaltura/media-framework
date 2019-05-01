CC = gcc -v
SRC = $(wildcard *.c)
SRC += $(wildcard ./utils/*.c)
SRC += $(wildcard ./common/*.c)
SRC += $(wildcard ./KMP/*.c)
SRC += $(wildcard ./transcode/*.c)
DEPS = $(wildcard *.h)
ODIR=obj
_OBJ = $(SRC:.c=.o)
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))
_EXE = transcoder
EXE = $(patsubst %,$(ODIR)/%,$(_EXE))
ifeq ($(OS), Linux)
        FFMPEG_LIB_DIR := ./ffmpeg
        X264_LIB_DIR := ./x264
else
        FFMPEG_LIB_DIR := ./ThirdParty/ffmpeg
        X264_LIB_DIR := ./ThirdParty/x264
endif

IDIRS = -I. -I$(FFMPEG_LIB_DIR) -I"./common" -I"./utils"  -I"./KMP" -I"./transcode"
LDIR = -L/usr/local/cuda/lib64 -L$(X264_LIB_DIR) -L$(FFMPEG_LIB_DIR)/libavfilter -L$(FFMPEG_LIB_DIR)/libswresample  -L$(FFMPEG_LIB_DIR)/libswscale -L$(FFMPEG_LIB_DIR)/libwresmple -L$(FFMPEG_LIB_DIR)/libavdevice -L$(FFMPEG_LIB_DIR)/libavutil -L$(FFMPEG_LIB_DIR)/libavformat -L$(FFMPEG_LIB_DIR)/libavcodec -L$(FFMPEG_LIB_DIR)/libpostproc -L/usr/local/lib
FFMPEG_LIBS = -lavfilter  -lavformat -lswscale  -lavcodec   -lavutil  -lswresample -lpostproc -lx264  
LIBS = -lm -lpthread  -lz -lbz2 -ldl 
CUDA_LIBS = -lnppig_static -lnppicc_static -lnppc_static -lnppidei_static -lcublas_static -lcudart_static -lculibos  -lcudart -lstdc++
CFLAGS = -Wall -g $(IDIRS) -fPIC  -static
LDFLAGS =  $(LDIR) $(LIBS)  $(FFMPEG_LIBS) $(LIBS) 
OS := $(shell uname)


ifeq ($(OS), Linux)
        LIBS += -lrt ${CUDA_LIBS} 
else
        LIBS += -liconv  -framework AudioToolbox  -framework VideoToolbox  -framework MediaToolbox  -framework CoreMedia  -framework CoreMediaIO  -framework CoreVideo   -framework CoreAudio  -framework CoreImage  -framework OpenGL   -framework AppKit  -framework QuartzCore  -framework ImageCaptureCore  -framework CoreFoundation  -framework Security   -framework SecurityFoundation  -framework SecurityInterface
endif

dir_guard=@mkdir -p $(@D)

$(ODIR)/%.o: %.c $(DEPS)        
	$(CC) -c -o $@ $< $(CFLAGS)

$(EXE): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(phony install): install

install: $(EXE)
	install $(EXE) ./

.PHONY: clean

clean:
	rm -rf $(ODIR) $(ODIR)/common/ $(ODIR)/utils/ $(ODIR)/KMP/ $(ODIR)/transcode/ $(EXE)
	mkdir $(ODIR)
	mkdir $(ODIR)/utils/
	mkdir $(ODIR)/common/
	mkdir $(ODIR)/KMP/
	mkdir $(ODIR)/transcode/

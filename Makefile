TARGET		 = main
SOURCES		 = main.c aes128_key.c
CL_SOURCES	 = aes128.cl

OBJECTS		:= ${SOURCES:.c=.o}

BITCODE		+= ${CL_SOURCES:.cl=.cpu32.bc}
BITCODE		+= ${CL_SOURCES:.cl=.cpu64.bc}
BITCODE		+= ${CL_SOURCES:.cl=.gpu32.bc}
BITCODE		+= ${CL_SOURCES:.cl=.gpu64.bc}

CC		 = cc
ARCHS		 = -arch i386 -arch x86_64
CFLAGS		 = -c -g -std=c11 -Wall -Wextra -pedantic
FRAMEWORKS	 = -framework OpenCL

CLC	 	 = /System/Library/Frameworks/OpenCL.framework/Libraries/openclc

.PHONY: all archive clean

all: $(TARGET)

archive:
	git archive -o archive.zip HEAD

clean:
	rm -rf archive.zip $(TARGET) $(BITCODE) $(OBJECTS)

$(TARGET): $(BITCODE) $(OBJECTS)
	$(CC)  $(OBJECTS) -o $@ $(FRAMEWORKS) $(ARCHS)

%.o: %.c
	$(CC)  $(CFLAGS) $(ARCHS) $< -o $@

%.cpu32.bc: %.cl
	$(CLC) -emit-llvm -c -arch i386 $< -o $@

%.cpu64.bc: %.cl
	$(CLC) -emit-llvm -c -arch x86_64 $< -o $@

%.gpu32.bc: %.cl
	$(CLC) -emit-llvm -c -arch gpu_32 $< -o $@

%.gpu64.bc: %.cl
	$(CLC) -emit-llvm -c -arch gpu_64 $< -o $@

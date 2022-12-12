ARCH := $(shell uname -m | sed 's/x86_64/x86/')

LIBBPFSRC = libbpf/src
LIBBPFOBJS = $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/libbpf_errno.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o $(LIBBPFSRC)/staticobjs/netlink.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/nlattr.o $(LIBBPFSRC)/staticobjs/str_error.o  $(LIBBPFSRC)/staticobjs/xsk.o

LDFLAGS += -lconfig -lelf -lz

all: clean libbpf ids
ids:
	mkdir -p build/
	clang -I $(LIBBPFSRC) -D__BPF__ -O2 -emit-llvm -c -o build/kern_ids.bc main.c
	llc -march=bpf -filetype=obj -o build/kern_ids.o build/kern_ids.bc
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -rf build/

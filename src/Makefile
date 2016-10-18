all: target
FORCE: ;
.PHONY: FORCE

target:	nfcd

%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	@$(CXX) $(CFLAGS) -c $< -o $@

%.o: %.cxx
	@$(CXX) $(CFLAGS) -c $< -o $@

nfcd: nfcd.o nfc-utils.o nfc-mfclassic.o nfc-mfultralight.o mifare.o debug.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o $(target)


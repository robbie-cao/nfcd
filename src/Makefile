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

nfcd: nfcd.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o $(target)


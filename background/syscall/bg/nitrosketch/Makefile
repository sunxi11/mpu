CC = g++
CFLAGS = -O2 -std=c++14 -g 
#$(PCAPPP_INCLUDES) $(PCAPPP_LIBS_DIR)
SSEFLAGS = -msse2 -mssse3 -msse4.1 -msse4.2 -mavx -march=native
sketchtestreq = ideal.o hash.o twotuple.o bloomfilter.o\
				flowradar.o mvsketch.o Pktextract.o main.o\
				hashpipe.o countmin.o MurmurHash3.o sketchvisor.o

HEADER += heavypart.h hash.h MurmurHash3.h lightpart.h bloomfilter.h parameter.h
#twotuple.h
#$(PCAPPP_LIBS)

sketchtest: $(sketchtestreq)
	$(CC) $(CFLAGS) $(SSEFLAGS) -o test $(sketchtestreq) -lpcap

ideal.o: ideal.h
	$(CC) $(CFLAGS) $(SSEFLAGS) -c ideal.h ideal.cpp

elasticsketch.o: elasticsketch.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c elasticSketch.h heavypart.h hash.h MurmurHash3.h lightpart.h

countsketch.o: countsketch.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c countsketch.h $(HEADER)

sketchlearn.o: sketchlearn.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c sketchlearn.h $(HEADER)

countbloomfilter.o: countbloomfilter.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c countbloomfilter.h $(HEADER)

hash.o: hash.h
	$(CC) $(CFLAGS) $(SSEFLAGS) -c hash.h hash.cpp

twotuple.o: twotuple.h
	$(CC) $(CFLAGS) $(SSEFLAGS) -c twotuple.h twotuple.cpp

MurmurHash3.o: MurmurHash3.h
	$(CC) $(CFLAGS) $(SSEFLAGS) -c MurmurHash3.h MurmurHash3.cpp

heavypart.o: heavypart.h $(HEADER) 
	$(CC) $(CFLAGS) $(SSEFLAGS) -c heavypart.h hash.h MurmurHash.h

lightpart.o: lightpart.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c hash.h lightpart.h MurmurHash.h

flowradar.o: flowradar.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c flowradar.h flowradar.cpp $(HEADER)

mvsketch.o: mvsketch.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c mvsketch.h mvsketch.cpp $(HEADER)

Pktextract.o: Pktextract.h
	$(CC) $(CFLAGS) $(SSEFLAGS) -c Pktextract.h Pktextract.cpp

hashpipe.o: hashpipe.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c hashpipe.h hashpipe.cpp $(HEADER)

main.o: sketchvisor.h countsketch.h sketchlearn.h countbloomfilter.h countheap.h univmon.h ideal.h elasticsketch.h flowradar.h mvsketch.h Pktextract.h main.cpp hashpipe.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c sketchvisor.h countsketch.h sketchlearn.h countbloomfilter.h countheap.h univmon.h bloomfilter.h ideal.h elasticsketch.h heavypart.h hash.h lightpart.h flowradar.h mvsketch.h Pktextract.h main.cpp hashpipe.h

countmin.o: countmin.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c countmin.h countmin.cpp $(HEADER)

sketchvisor.o: sketchvisor.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c sketchvisor.h sketchvisor.cpp $(HEADER)

bloomfilter.o: bloomfilter.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c bloomfilter.cpp $(HEADER)

univmon.o: univmon.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c univmon.h $(HEADER)

countheap.o: countheap.h $(HEADER)
	$(CC) $(CFLAGS) $(SSEFLAGS) -c countheap.h $(HEADER)

.PHONY : clean
clean:
	rm $(sketchtestreq) test *.gch *.txt

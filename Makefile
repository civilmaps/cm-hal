FLAGS = -std=c++11 -Wall -g -fPIC -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS -fopenmp 

CXX=g++

LIBS=$(LIBS_CM) -lPocoFoundation -lPocoNet  -lPocoUtil -lPocoCrypto -lPocoXML -lcurl -lpcap -lssl -ljson $(EXTRALIBS)

TST_LSR_OBJS=tests/test_laser_reader.o src/hal/laser_io.o

.PHONY : clean all

all: test_laser_reader
-include $(OBJS:.o=.d)

%.o: %.cpp
	$(CXX) -c $(FLAGS) $*.cpp -o $*.o
	$(CXX) -MM $(FLAGS) $*.cpp > $*.d
	
test_laser_reader : $(TST_LSR_OBJS) 
	$(CXX) -o tests/test_laser_reader $(TST_LSR_OBJS) $(FLAGS) -pedantic -I $(LIBS)

clean:
	/bin/rm -f $(OBJS) $(TST_LSR_OBJS) *.d *.o *.so */*.d

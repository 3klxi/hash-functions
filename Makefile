CXX = g++
CXXFLAGS = -std=c++11 -Wall
LDFLAGS = -ltomcrypt

TARGET = main 
SRCS = main.cpp MD5.cpp SHA-1.cpp SHA-256.cpp SHA-512.cpp File_hash_LibTomCrypt.cpp File_hash_self.cpp

$(TARGET): $(SRCS)
	$(CXX) $(SRCS) -o $(TARGET) $(CXXFLAGS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

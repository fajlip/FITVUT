CC = g++
FLAGS = 
RESULT = roughDNS
LOGIN = xbrezn00
OTHER = makefile README manual.pdf
SOURCE = parser.cpp roughDNS.cpp mssg_response.cpp
HEADS = parser.h mssg_def.h mssg_class.h
FILES = $(SOURCE) $(HEADS) $(OTHER)

$(RESULT):
	$(CC) $(FLAGS) $(SOURCE) -o $(RESULT)

tar:
	tar -cvzf $(LOGIN).tgz $(FILES)
	

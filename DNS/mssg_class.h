#include <stdint.h>
#include <string>
#include <vector>
#include <utility>
#include "mssg_def.h"
#include "parser.h"


#pragma once

typedef uint8_t buffer_t;

class dns_server
{
public:
	dns_message query;
	bool MitM;
	uint8_t QnameByte_size;

	std::vector<uint8_t> QnameByte;
	std::string Qname, IPStr, zonefile; // pro vystup
	std::vector<std::pair<std::string, uint8_t> > usedNames;
	uint32_t tracker;
	Parser parser;

public:
	void decode(buffer_t *buffer);
	void reply(buffer_t *buffer);
	uint32_t strToIP(std::string &strIP);
	std::vector<buffer_t> NameToBytes(std::string &name);
	void addName(std::string &str, uint8_t offset);
	uint8_t searchName(std::string &str);
	bool response_A(buffer_t *responseBuffer);
	bool response_MX(buffer_t *responseBuffer);
};


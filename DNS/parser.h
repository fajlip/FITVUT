#pragma once

#include <string>
#include <vector>
#include <stdint.h>
#include <fstream>


typedef enum
{
	ST_START = 0,
	ST_VAR,
	ST_NUMBER,
	ST_NAME,
	ST_CLASS,
	ST_TYPE,
	ST_COMMENT,
	ST_REFERENCE,
	ST_LPAR,
	ST_RPAR,
	ST_IP,
	ST_END,
	ST_EOF,
	ST_ERROR
} State;

typedef struct
{
	State state;
	std::string value;
} Token;

typedef struct
{
	int32_t ttl;
	bool ttlset;
	std::string name, cls, type, opt, rdata;
} LData;

typedef struct
{
	std::string mname, rname;	// name server, mailbox
	uint32_t serial, minimum;
	int32_t  refresh, retry, expire;
} SOA;

typedef struct
{
	int32_t ttl;
	std::string name, ip;
} A;

typedef struct
{
	int32_t ttl;
	int16_t preference;
	std::string host;
} MX;

typedef struct
{
	int32_t ttl;
	std::string host;
} NS;

class Parser
{
public:
	std::ifstream file;
	int32_t TTL;
	std::string ORIGIN;
	SOA SOA_record;
	std::vector<A>	A_records;
	std::vector<MX>	MX_records;
	std::vector<NS> NS_records;
	
	Token getToken();
	bool isType(std::string &);
	int32_t makeNum(std::string &);
	uint32_t makeUNum(std::string &);
public:
	bool parse(const char *);
	void printZone();
};

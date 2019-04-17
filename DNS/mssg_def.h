#pragma once

#include <string>

struct dns_message
{
	// tato slova utvari hlavicku - celkem 12 bytu
	uint16_t ID, flags, QDcount, ANcount, NScount, ARcount;
	// url
	std::string Qname;
	// url a tato slova utvari query sekci
	uint16_t Qtype, Qclass;
	
};

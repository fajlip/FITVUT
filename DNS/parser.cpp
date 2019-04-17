#include "parser.h"
#include <algorithm>
#include <fstream>
#include <string>

#include <iostream>
#include <ctype.h>


bool Parser::parse(const char *filename)
{
	// otevre string stream ze suboru
	file.open(filename, std::ifstream::in);
	// pokud se nepovedlo otevrit soubor
	
	if (!file.is_open())
		return false;

	bool originset = false, ttlset = false;
	Token t;
	// parsovani hlavicky
	// <head>	-> <var> <soa>
	// <var>	-> $GLOBAL <value> <var>
	// <var>	-> $TTL <value> <var>
	// <var>	-> <eps>
	t = getToken();
	
	while (t.state == ST_VAR)
	{
		if (t.value == "$ORIGIN")
		{
			t = getToken();
			if (t.state == ST_NAME)
			{
				originset = true;
				ORIGIN = t.value;
			}
		}
		else if (t.value == "$TTL")
		{
			t = getToken();
			if (t.state == ST_NUMBER)
			{
				ttlset = true;
				TTL = makeNum(t.value);
			}
		}
		t = getToken();
	}
	// <soa>	-> <domain> <ttl> IN SOA <root> <mail> ( <serial> <refresh> <retry> <expire> <minimum> )
	// <domain>	-> <value>
	// <domain>	-> @
	// <ttl>	-> <value>
	// <ttl>	-> <eps>
	// <root>	-> <value>
	// <mail>	-> <value>
	// <serial>	-> <value>
	// <refresh>	-> <value>
	// <retry>	-> <value>
	// <expire>	-> <value>
	// <minimum>	-> <value>

	if (t.state == ST_NAME)
	{
		if (!originset) {
			ORIGIN = t.value;
			originset = true;
		}
	}
	else if (t.state == ST_REFERENCE)
	{
		if (!originset)
			return false;
	}
	else
		return false;
	
	t = getToken();

	// nasleduje bud TTL nebo <class> (IN)
	if (t.state == ST_NUMBER)
	{
		if (!ttlset) {
			TTL = makeNum(t.value);
			ttlset = true;
		}
		t = getToken();
	}
	
	if (t.state == ST_CLASS)
	{
		// v tomto bode uz musi byt ttl nastavene
		if (!ttlset)
			return false;
		if (t.value != "IN")
			return false;
	}

	t = getToken();
	
	// nasleduje SOA
	
	if (t.state == ST_TYPE)
	{
		if (t.value != "SOA")
			return false;
	}

	t = getToken();
	
	// nasleduje <root>
	
	if (t.state == ST_NAME)
	{
		SOA_record.mname = t.value;
	} else return false;

	t = getToken();
	
	// nasleduje <mail>
	
	if (t.state == ST_NAME)
	{
		SOA_record.rname = t.value;
	} else return false;

	t = getToken();

	// nasleduje znak zavorky '('

	if (t.state != ST_LPAR)
		return false;

	t = getToken();
	
	// nasleduje serial
	if (t.state == ST_NUMBER)
		SOA_record.serial = makeUNum(t.value);
	else 
		return false;
	
	t = getToken();

	// nasleduje refresh
	if (t.state = ST_NUMBER)
		SOA_record.refresh = makeNum(t.value);
	else
		return false;
	
	t = getToken();

	// nasleduje retry
	if (t.state = ST_NUMBER)
		SOA_record.retry = makeNum(t.value);
	else
		return false;

	t = getToken();

	// nasleduje expire
	if (t.state = ST_NUMBER)
		SOA_record.expire = makeNum(t.value);
	else
		return false;

	t = getToken();
	
	// nasleduje minimum
	if (t.state == ST_NUMBER)
		SOA_record.minimum = makeUNum(t.value);
	else
		return false;

	t = getToken();

	// nasleduje uzavrena zavorka ')' (a zaroven konec hlavicky)
	if (t.state != ST_RPAR)
		return false;

	t = getToken();

	// zacatek tela
	// <body>	-> <record>
	// <record>	-> <eps>
	// <record>	-> <cells> <record>
	// <cells>	-> <name> <ttl> <class> <type> <rdata>
	// <name>	-> <eps>
	// <name>	-> @
	// <ttl>	-> <value>
	// <ttl>	-> <eps>
	// <class>	-> IN
	// <class>	-> <eps>
	// <type>	-> A
	// <type>	-> MX
	// <rdata>	-> <value>
	// <rdata>	-> <value> <value>
	
	A atemp;
	MX mxtemp;
	NS nstemp;
	LData ldata;
	while(t.state != ST_EOF)
	{
	
		ldata.ttlset = false;
		
		// name muze byt prazdne
		if (t.state == ST_NAME)
		{
			ldata.name = t.value;
			t = getToken();
		}
		else if (t.state == ST_REFERENCE)
		{
			ldata.name = ORIGIN;
			t = getToken();
		}
		// nasleduje ttl, ktere taky muze byt prazdne
		if (t.state == ST_NUMBER)
		{
			ldata.ttl = atoi(t.value.c_str());
			ldata.ttlset = true;
			t = getToken();
		}
		// nasleduje class, ktere muze byt taky prazdne
		if (t.state == ST_CLASS)
		{
			ldata.cls = t.value;
			t = getToken();
		}
		// nasleduje type, ktery musi byt pritomen
		if (t.state == ST_TYPE)
		{
			ldata.type = t.value;
		}
		else if (t.state == ST_NAME)
		{ // nerozpoznali jsme podporovane typy
			// TODO ... netusim jak zatim
		}
		else
			return false;
		
		t = getToken();

		// nasleduji rdata
		// priorita u MX (nemusi byt vsude)
		if (t.state == ST_NUMBER)
		{ 
			ldata.opt = t.value;
			t = getToken();
		}
		// koncovy zaznam
		if (t.state == ST_IP)
		{ 
			ldata.rdata = t.value;
		}
		else if (t.state == ST_NAME)
		{
			ldata.rdata = t.value;
		}

		if (ldata.type == "A")
		{
			// nastavime ttl
			if (ttlset)
				atemp.ttl = ldata.ttl;
			else
				atemp.ttl = TTL;
			
			// nastavime domenu
			if (!ldata.name.empty())
				atemp.name = ldata.name;
			
			else if (ldata.name == "@")
				atemp.name = ORIGIN;
			
			else
				atemp.name = ORIGIN;
			
			// nastavime IP
			if (ldata.rdata.empty())
				return false;
			
			atemp.ip = ldata.rdata;
			
			A_records.push_back(atemp);
		}

		else if (ldata.type == "MX")
		{
			// ttl
			if (ttlset)
				mxtemp.ttl = ldata.ttl;
			else
				mxtemp.ttl = TTL;
			// domena nas nezajima
			// preference
			if (!ldata.opt.empty())
				mxtemp.preference = static_cast<int16_t>(atoi(ldata.opt.c_str()));
			else
				return false;
			// host
			if (ldata.rdata.empty())
				return false;

			mxtemp.host = ldata.rdata;

			MX_records.push_back(mxtemp);
		}
		else if (ldata.type == "NS")
		{
			// ttl
			if (ttlset) nstemp.ttl = ldata.ttl;
			// zajimaji nas jen rdata
			if (ldata.rdata.empty())
				return false;

			nstemp.host = ldata.rdata;
			NS_records.push_back(nstemp);
		}

		t = getToken();
	}

	return true;
}

Token Parser::getToken()
{
	int c;
	State state = ST_START;
	Token token;
	token.state = ST_START;
	token.value.clear();
	bool advance = true;
	while (advance) {
		c = file.get();
		switch(state) {
		case ST_START:
			if (isspace(c))
				continue;

			else if (isdigit(c))
				state = ST_NUMBER;
			else if (isalpha(c))
				state = ST_NAME;
			else if (c == '$')
				state = ST_VAR;
			else if (c == ';')
			{
				state = ST_COMMENT;
				break;
			}
			else if (c == '@')
				state = ST_REFERENCE;
			else if (c == '(')
				state = ST_LPAR;
			else if (c == ')')
				state = ST_RPAR;
			else if (c == -1)
			{
				state = ST_EOF;
				break;
			}
			else
			{
				state = ST_ERROR;
				break;
			}

		token.value.append((char *)&c);
		break;

		case ST_NUMBER:
			if (isdigit(c))
			{
				state = ST_NUMBER;
				token.value.append((char *)&c);
			}
			else if ((c == 'D') || (c == 'W') || (c == 'H'))
			{
				state = ST_END;
				token.state = ST_NUMBER;
				token.value.append((char *)&c);
			}
			else if (c == '.')
			{
				state = ST_IP;
				token.value.append((char *)&c);
			}
			else
			{
				state = ST_END;
				token.state = ST_NUMBER;
				file.unget();
			}

		break;

		case ST_IP:
			if (isdigit(c) || (c == '.'))
			{
				state = ST_IP;
				token.value.append((char *)&c);
			}
			else
			{
				state = ST_END;
				token.state = ST_IP;
				file.unget();
			}

		break;

		case ST_COMMENT:
			if (c == '\n')
				state = ST_START;
			else if (c == -1)
				state = ST_EOF;
			else
				state = ST_COMMENT;
		break;	

		case ST_REFERENCE:
			state = ST_END;
			token.state = ST_REFERENCE;
			file.unget();
		break;

		case ST_VAR:
			if (isalpha(c))
			{
				state = ST_VAR;
				token.value.append((char *)&c);
			}
			else
			{
				state = ST_END;
				token.state = ST_VAR;
				file.unget();
			}

		break;
		case ST_NAME:

			if (isdigit(c) || isalpha(c) || (c == '.') || (c == '-'))
			{
				state = ST_NAME;
				token.value.append((char *)&c);
			}

			else
			{
				if (token.value == "IN")
					token.state = ST_CLASS;
				else if (isType(token.value))
					token.state = ST_TYPE;
				else
					token.state = ST_NAME;

				state = ST_END;
				file.unget();
			}

		break;

		case ST_LPAR:
			state = ST_END;
			token.state = ST_LPAR;
			file.unget();
		break;

		case ST_RPAR:
			state = ST_END;
			token.state = ST_RPAR;
			file.unget();
		break;

		case ST_EOF:
			state = ST_END;
			token.state = ST_EOF;
			file.unget();
		break;

		case ST_END:
			advance = false;
			file.unget();
		break;

		}
	}
	return token;
}

bool Parser::isType(std::string &value)
{
	std::vector<std::string> types;
	types.push_back("SOA");
	types.push_back("A");
	types.push_back("MX");
	types.push_back("NS");
//	types.push_back("AAAA");
//	types.push_back("CNAME");
//	types.push_back("TXT");
	for (unsigned int i = 0; i < types.size(); i++)
	{
		if (types[i] == value)
			return true;
	}
	return false;
}


void Parser::printZone()
{
	std::cout << "{" << std::endl;
	std::cout << "\t\"$ORIGIN\": \"" << ORIGIN << "\"," << std::endl;
	std::cout << "\t\"$TTL\": \"" << TTL << "\"," << std::endl;
	std::cout << "\t\"SOA\": {" << std::endl;
	std::cout << "\t\t\"mname\": \"" << SOA_record.mname << std::endl;
	std::cout << "\t\t\"rname\": \"" << SOA_record.rname << std::endl;
	std::cout << "\t\t\"serial\": \"" << SOA_record.serial << std::endl;
	std::cout << "\t\t\"refresh\": \"" << SOA_record.refresh << std::endl;
	std::cout << "\t\t\"retry\": \"" << SOA_record.retry << std::endl;
	std::cout << "\t\t\"expire\": " << SOA_record.expire << std::endl;
	std::cout << "\t\t\"minimum\": " << SOA_record.minimum << std::endl;
	std::cout << "\t}," << std::endl;
	std::cout << "\t\"NS\": [" << std::endl;

	for (unsigned int i = 0; i < NS_records.size(); i++)
	{
		std::cout << "\t\t{ \"host\": \"" << NS_records[i].host << "\" }";
		if ((i + 1) != NS_records.size())
				std::cout << ",";
		std::cout << std::endl;
	}
	std::cout << "\t]," << std::endl;
	std::cout << "\t\"A\": [" << std::endl;

	for (unsigned int i = 0; i < A_records.size(); i++)
	{
		std::cout << "\t\t{ \"name\": \"" << A_records[i].name << "\", \"ip\": \"";
		std::cout << A_records[i].ip << "\" }";
		if ((i + 1) != A_records.size())
			std::cout << ",";
		std::cout << std::endl;
	}

	std::cout << "\t]," << std::endl;
	std::cout << "\t\"MX\": [" << std::endl;
	for (unsigned int i = 0; i < MX_records.size(); i++)
	{
		std::cout << "\t\t{ \"preference\": " << MX_records[i].preference << ", ";
		std::cout << "\"host\": \"" << MX_records[i].host << "\" }";
		if ((i + 1) != MX_records.size())
			std::cout << ",";
		std::cout << std::endl;
	}

	std::cout << "\t]" << std::endl;
	std::cout << "}" << std::endl;
}

int32_t Parser::makeNum(std::string &str)
{
	if (isdigit(str[str.length() - 1]))
		return static_cast<int32_t>(atoi(str.c_str()));
	
	else if (str[str.length() - 1] == 'H')
		return static_cast<int32_t>(atoi(str.c_str())) * 3600;
	
	else if (str[str.length() - 1] == 'D')
		return static_cast<int32_t>(atoi(str.c_str())) * 86400;
	
	else if (str[str.length() - 1] == 'W')
		return static_cast<int32_t>(atoi(str.c_str())) * 604800;
}

uint32_t Parser::makeUNum(std::string &str)
{
	if (isdigit(str[str.length() - 1]))
		return static_cast<uint32_t>(atoi(str.c_str()));
	
	else if (str[str.length() - 1] == 'H')
		return static_cast<uint32_t>(atoi(str.c_str())) * 3600;
	
	else if (str[str.length() - 1] == 'D')
		return static_cast<uint32_t>(atoi(str.c_str())) * 86400;
	
	else if (str[str.length() - 1] == 'W')
		return static_cast<uint32_t>(atoi(str.c_str())) * 604800;
}

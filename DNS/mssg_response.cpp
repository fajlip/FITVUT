#include <iostream> //standardni knihovna
#include <stdio.h> //kvuli stderr
#include <cstdlib>
#include <string.h>
#include "mssg_class.h"
#include "parser.h"
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <iomanip>  //setw

#define INF_HEADER_SIZE 12
#define BUFFSIZE 512

/*
Hlavicka DNS zpravy z RFC 1035

	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       | //be e6 
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | //01 + 00 -> Truncated
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    | //00 01
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    | //00 00
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    | //00 00 
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    | //00 00
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

using namespace std;

void dns_server::decode (buffer_t *buffer)
{
	// hlavicka ma pevne danych 12 bytu
	memcpy(&query, buffer, sizeof(uint16_t) * 6);


	/* ----SEKCE PRO KONKRETNI QUERY REQUEST-------------
	z RFC 1035
	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     / //08 77 
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     | //65 62
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    | //73 68
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	*/

    //counter bude preskakovat 12 bytovou hlavicku
    int counter = INF_HEADER_SIZE;
    uint8_t Qname_size = 0;
    uint8_t Qname_sizeTotal = 0;
    
    char help; 

    memcpy(&Qname_size, buffer + counter, 1);

    //pokud je Qname_size rovno nule, pak již nebude nasledovat dalsi cast nazvu
    while (Qname_size != 0)
    {
    	//+1 kvuli nulovemu indexovani
    	for (int i = 1; i < Qname_size+1; i++)
    	{
    		memcpy(&help, buffer + counter + i, 1);
    		//pridavame znaky do stringoveho Qname, budeme ho potrebovat na hledani v zonefile		
    		Qname.append(&help);
    	}

    	//pridame tecku, protoze ma nasledovat do url
    	Qname.append(".");
    	query.Qname = Qname;

    	counter += (int)Qname_size + 1;

    	//aktualizujeme Qname_size, cast nazvu byla jiz prectena, nasleduje dalsi
    	memcpy(&Qname_size, buffer+counter, 1);

    }

	//odmazeme tecku na konci Qname
	Qname = Qname.substr(0, Qname.size()-1);


	//jeste musime prevest Qname na skutecne byty; budeme vracet v response
	QnameByte_size = counter-INF_HEADER_SIZE + 1; // + root nula na konec

	QnameByte.resize(QnameByte_size);
	memcpy(static_cast<void *>(&QnameByte.at(0)), buffer+INF_HEADER_SIZE,  QnameByte_size);

	// pridame Qname do polozky pouzitych jmen
	addName(Qname, INF_HEADER_SIZE);

	//specifikujeme Qtype
	memcpy(&query.Qtype, buffer+counter+1,2);
	//specifikuje class pozadavku. Pro internet je to IN 
	memcpy(&query.Qclass, buffer+counter+3,2);

	//			  A                 MX			             SOA
	if ((query.Qtype != 1) && (query.Qtype != 15) && (query.Qtype != 6))
		//dorazil nepodporovany typ DNS zaznamu. Nezajem; Error 4 not implemented
		query.flags  |= (1u << 3);

	return;
}

void dns_server::addName(std::string &str, uint8_t offset)
{
	string temp = str;
	usedNames.push_back(make_pair(temp, offset));
	temp.append(".");
	size_t pos;
	while (true)
	{
		pos = temp.find_first_of(".");
		temp.erase(0, pos + 1);
		if (temp.empty())
			break;
		usedNames.push_back(make_pair(temp.substr(0, temp.length() - 1), offset + pos));
	}
}

uint8_t dns_server::searchName(std::string &str)
{
	// situace, kdy je str podretezec v hledanem retezci
	for (int i = 0; i < usedNames.size(); ++i)
	{
		if (usedNames[i].first.find(str) == 0)
			return usedNames[i].second;
	}
	// ohlasuje chybu, protoze posun je minimalne 12 bytu
	return 0; 
}

//funkce pro prevod string IP adresy na odpovidajici ciselnou adresu pro prenos klientovi
uint32_t dns_server::strToIP(string &strIP)
{
	string tmp = strIP;
	uint8_t temp[4] = { 0x0, 0x0, 0x0, 0x0 };

	tmp.append(".");

	size_t pos = string::npos;

	uint32_t result;

	for (unsigned int i = 0; i < 4; i++)
	{
	
	 	pos = tmp.find_first_of(".");
 		result = atoi(tmp.substr(0, pos).c_str());
 		tmp.erase(0, pos + 1);
  	
  		if (result > 255)
  	 		return 0;
  	
  		temp[i] = static_cast<uint8_t>(result);
 }

	memcpy(&result, temp, sizeof(uint32_t));

	return result; 
}

//funkce pro prevod string domeny na odpovidajici ciselnou reprezenci pro prenos klientovi . '.' jsou nahrazeny
vector<buffer_t> dns_server::NameToBytes(string &name)
{
	string temp = name;
	vector<buffer_t> result;
	temp.append(".");
	size_t pos, len;

	result.push_back(0x0);
	pos = temp.find_first_of(".");
	while (pos != string::npos)
	{

		len = temp.substr(0, pos).length();
		result[result.size() - 1] = static_cast<buffer_t>(len);
		result.resize(result.size() + len);
		memcpy((void*)&result.at(result.size() - len), &temp.substr(0, pos)[0], sizeof(buffer_t) * len);
		temp.erase(0, pos + 1);
		pos = temp.find_first_of(".");
	}

	//z nejakeho duvodu se na konci objevuje vice nul nez jedna, tak je odstaranime
	while (result[result.size() - 1] == 0x0)
		result.pop_back();

	return result;
}

void dns_server::reply(buffer_t *responseBuffer)
{
	//## NASTAVENI FLAGU ## - DORESIT TREBA RA

	//zmeni prvni bit zleva flagu na 1, tudiz se bude nyni jednat o zpravu response
	uint16_t mask = 0b1000000000000000;
	mask = htons(mask);
	uint8_t flagy[2];
	//query.flags = htons(query.flags);
	memcpy(flagy, &mask, sizeof(uint16_t));



	query.flags = query.flags | mask;
	query.flags = htons(query.flags);


	// ## NAPLNIME BUFFER ## 
	//__________________________________________________

	memcpy(responseBuffer, &query.ID, sizeof(uint16_t));
	memcpy(responseBuffer+sizeof(uint16_t), &mask, sizeof(uint16_t));
	memcpy(responseBuffer+2*sizeof(uint16_t), &query.QDcount, sizeof(uint16_t));


	//----------queries-------------
	memcpy(responseBuffer+INF_HEADER_SIZE*sizeof(uint8_t), static_cast<void *>(&QnameByte.at(0)), QnameByte_size);
	memcpy(responseBuffer+INF_HEADER_SIZE*sizeof(uint8_t)+QnameByte_size, &query.Qtype, sizeof(uint16_t));
	memcpy(responseBuffer+INF_HEADER_SIZE*sizeof(uint8_t)+QnameByte_size + sizeof(uint16_t), &query.Qclass, sizeof(uint16_t));

	//-----------answers----------------------------
	/*response z RFC 1035
	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    //podle RFC

    uint16_t RDLength;
    uint32_t ATTLout;
    uint32_t NSTTLout;
   	string RData;

   	//pocatecni nastaveni trackeru
   	tracker = INF_HEADER_SIZE + QnameByte.size() + sizeof(uint16_t) * 2;


    //parse zonefile
	bool parserResult = parser.parse(zonefile.c_str());

	//pokud se parse nepovedl doslo k chybe
	if (!parserResult)
	{
		cerr << "## ERROR ## Zonefile parse failed. Sincerest apologies." << endl;
		exit(1);
	}

	//## jdeme prohledat zonefile ##
	//___________________________________________________________

	//globalni TTL
	uint16_t TTLout = parser.TTL;
	//bool found = false;
	string Qname_temp = Qname;
	Qname_temp.append(".");

	//vyresetujeme tyto promenne, pro jistotu
	query.ANcount = query.NScount = query.ARcount = 0;
	
	// A
	if (htons(query.Qtype) == 1)
	{
		//pokud nebyl nalezen A zaznam
		if (!response_A(responseBuffer))
		{
			cout << "nic se nenaslo" << endl;
			return;
		}
	}
	
	// MX
	else if (htons(query.Qtype) == 15)
	{
		//pokud nebyl nalezen MX zaznam
		if (!response_MX(responseBuffer))
		{
			cout << "nic nebylo nalezenooooo" << endl;
			return;
		}
	}

	//je nutne provest htons jeste pred ulozenim do bufferu
	query.ANcount = htons(query.ANcount);
	query.NScount = htons(query.NScount);
	query.ARcount = htons(query.ARcount);

	//prepiseme novou hodnotou, puvodni nuly
	memcpy(responseBuffer+3*sizeof(uint16_t), &query.ANcount, sizeof(uint16_t));
	memcpy(responseBuffer+4*sizeof(uint16_t), &query.NScount, sizeof(uint16_t));
	memcpy(responseBuffer+5*sizeof(uint16_t), &query.ARcount, sizeof(uint16_t));
	
	return;

}

bool dns_server::response_A(buffer_t *responseBuffer)
{
	string RData;
	string Qname_temp = Qname;
	Qname_temp.append(".");
	uint16_t RDLength;
	uint32_t ATTLout;
	bool found = false;
	//zkusime vyplnit answers
	for (unsigned int i = 0; i < parser.A_records.size(); i++)
	{
		//pokud se shoduje zaznam presne s nasim
		if (parser.A_records[i].name == Qname_temp)
		{
			//odpoved nalezena
			query.ANcount = 1;
			
			//4 protoze se jedna o IPv4 adresu a ta ma 4 byty
			RDLength = 4;
			//do polozky Rdata pridam ip adresu ze zonefile, nyni ji mam ve stringu
			RData = parser.A_records[i].ip;
			//podivam se zda nema polozka unikatni time to live
			if (parser.TTL != parser.A_records[i].ttl)
				ATTLout = parser.A_records[i].ttl;

			found = true;
			break;
		}
	}
	if (found)
	{
		uint16_t Name = 0xc000 + searchName(Qname);
		Name = htons(Name);

		//---------answers--------------
		//pridavame polozky z answer jednu po druhe
		//16 bitová polozka name
		memcpy(responseBuffer+tracker*sizeof(uint8_t), &Name, sizeof(uint16_t));
		tracker += sizeof(uint16_t);

		//16 bitová polozka Qtype v nasem pripade A
		memcpy(responseBuffer+tracker*sizeof(uint8_t), &query.Qtype, sizeof(uint16_t));
		tracker += sizeof(uint16_t);

		//16 bitová polozka Qclass, obvykle IN
		memcpy(responseBuffer+tracker*sizeof(uint8_t), &query.Qclass, sizeof(uint16_t));
		tracker += sizeof(uint16_t);

		//32 bitová polozka TTL, nemusi byt globalni TTL, ale muze
		memcpy(responseBuffer+tracker*sizeof(uint8_t), &ATTLout, sizeof(uint32_t));
		tracker += sizeof(uint32_t);

		RDLength = htons(RDLength);

		memcpy(responseBuffer+tracker*sizeof(uint8_t), &RDLength, sizeof(uint16_t));
		tracker += sizeof(uint16_t);
		
		//mitm utok, podstrcime falesnou adresu
		if (MitM)
			RData = IPStr;

		//prevod string adresy na IP adresu v hex
		uint32_t RDataHex = strToIP(RData);

		//pridame IP adresu do bufferu
		memcpy(responseBuffer+tracker*sizeof(uint8_t), &RDataHex, sizeof(uint32_t));
		tracker += sizeof(uint32_t);
		

		//vypis ala wireshark
		cout << "q: " << Qname << ": type A, class IN" << endl;
		cout << "r: " << Qname << ": type A, class IN"  << ", addr " << RData << endl;


		return true;
	}
	else
		return false;

}

bool dns_server::response_MX(buffer_t *responseBuffer)
{
	cout << "q: " << Qname << ": type MX, class IN" << endl;

	//pokud nemame zadne MX zaznamy ve vlastnim zonefile, pak se budeme muset ptat rekurzivne
	if (parser.MX_records.size() == 0)
		return false;

	string Qname_temp = Qname;
	//Qname_temp.append(".");
	vector<uint8_t> byty;
	for (int i = 0; i < parser.MX_records.size(); i++)
	{
		//answer nalezen
		query.ANcount += 1;
		uint16_t Name = 0xc000 + searchName(Qname);

		Name = htons(Name);

		memcpy(responseBuffer + tracker*sizeof(uint8_t), &Name, sizeof(uint16_t));
		tracker += sizeof(uint16_t);

		memcpy(responseBuffer + tracker*sizeof(uint8_t), &query.Qtype, sizeof(uint16_t));
		tracker += sizeof(uint16_t);

		memcpy(responseBuffer + tracker*sizeof(uint8_t), &query.Qclass, sizeof(uint16_t));
		tracker += sizeof(uint16_t);

		int32_t ttl = parser.MX_records[i].ttl;

		if (ttl == 0)
			ttl = parser.TTL;

		ttl = htonl(ttl);

		memcpy(responseBuffer + tracker*sizeof(uint8_t), &ttl, sizeof(int32_t));
		tracker += sizeof(int32_t);

		//data length zatim netusime
		uint32_t temp_track = tracker;
		uint16_t dataLength = 0x0;

		memcpy(responseBuffer + tracker*sizeof(uint8_t), &dataLength, sizeof(uint16_t));
		tracker += sizeof(uint16_t);

		uint16_t prefs = parser.MX_records[i].preference;
		prefs = htons(prefs);
		memcpy(responseBuffer + tracker*sizeof(uint8_t), &prefs, sizeof(uint16_t));

		tracker += sizeof(uint16_t);
		dataLength += sizeof(uint16_t);
		byty = NameToBytes(parser.MX_records[i].host);

		memcpy(responseBuffer + tracker*sizeof(uint8_t), (void*)&byty.at(0), byty.size());
		tracker += byty.size();

		dataLength += byty.size();

		dataLength = htons(dataLength);
		memcpy(responseBuffer + temp_track*sizeof(uint8_t), &dataLength, sizeof(uint16_t));
		cout << "r: " << Qname << ": type MX, class IN, preference " << dec << htons(prefs) << ", mx " << parser.MX_records[i].host << endl;
	}

	return true;
}

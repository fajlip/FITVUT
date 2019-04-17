/*
	Autor: Brezna Filip
	Login: xbrezn00
	Project name: roughDNS
*/	

#include <iostream> //standardni knihovna
#include <stdio.h> //kvuli stderr
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h> //sockaddr_in
#include <sys/types.h>  //funkce jako bind
#include <sys/socket.h> 
#include <unistd.h> //fork
#include <vector>
#include <iomanip>
#include "mssg_class.h"

using namespace std;

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define MAX_QUEUE 5
//max size of dns message
#define BUFFSIZE 512

//SOA - Start of Authority
//A - IPv4 adresy
//MX - SMTP Mail Exchangers

int port = 53;							
//string zonefile = "zonefile.txt";

//kontrola portu
int portCheck (string portStr)
{
	char * pEnd;
	int result = strtol (portStr.c_str(), &pEnd, 10);

	//prekontrolovat hranice
	if (*pEnd != '\0' || result < 1 || result > 65535)
	{
		cerr << "## ERROR ## Invalid port number." << endl;
		exit (EXIT_SUCCESS);
	}

	return result;
}


void checkArguments(int argc, char** argv, dns_server &dns)
{
	//byl spravne zadan help
	if ((string(argv[1]) == "--help") || (string(argv[1]) == "-h"))
	{
		cout << "This is help for: " << string(argv[0]) << endl << "-p [--port] specifies port number, which is next argument" << endl;
		cout << "-m [--mitm] 'Man in the middle attack' A and MX queries responded with IP that is following this command." << endl;
		cout << "Last argument ALWAYS specifies zonefile with his name." << endl;
		exit (EXIT_SUCCESS);
	}

	if (argc == 1)
	{
		cerr << "## ERROR ## No arguments. You can use --help." << endl;
		exit (EXIT_SUCCESS);
	}
	
	dns.zonefile = argv[argc-1];

	if ((argc == 4) || (argc == 6))
	{
		//pokud byl port nalezen na prvni pozici
		
		if ((string(argv[1]) == "-p") || (string(argv[1]) == "--port"))
		{	
			string portStr = string(argv[2]);
			//funkce na kontrolu portu
			port = portCheck(portStr);
		}

		//pokud byl port nalezen na treti pozici
		else if ((string(argv[3]) == "-p") || (string(argv[3]) == "--port"))
		{	
			string portStr = string(argv[4]);
			port = portCheck(portStr);
		}

		//pokud byl MitM nalezen na prvni pozici
		if ((string(argv[1]) == "-m") || (string(argv[1]) == "--mitm"))
		{		
			dns.IPStr = string(argv[2]);
			dns.MitM = true;
		}

		//pokud byl MitM nalezen na treti pozici
		else if ((string(argv[3]) == "-m") || (string(argv[3]) == "--mitm"))
		{	
			dns.IPStr = string(argv[4]);
			dns.MitM = true;
		}

	}

	//argumenty nejsou validni
	else if (argc != 2)
	{
		cerr << "## ERROR ## Invalid arguments. You can use --help." << endl;
		exit (EXIT_FAILURE); //Failure?
	}

	//kontrola IP
	return;
}

int main (int argc, char** argv)
{
	// jadro programu
	dns_server DNS_SERVER;
	// zchecknuti argumentu
	
		checkArguments(argc, argv, DNS_SERVER);

	struct sockaddr_in server,client;
	int ipv4_socket;
	socklen_t sizeofServer;
	
	//vytvorime socket; AF_INET = IPv4; SOCK_DGRAM = UDP komunikace 
	ipv4_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (ipv4_socket < 0)
	{
		cerr << "## ERROR ## Broken socket." << endl;
		return EXIT_FAILURE;
	}	

	//naplneni struktury sockaddr_in
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	//host interface address in network byte order
	server.sin_addr.s_addr = INADDR_ANY;

	//bindne jmeno na socket
	if (bind(ipv4_socket, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		cerr << "## ERROR ## Bind was unsuccessful." << endl;
		return EXIT_FAILURE;
	}	

	//---------------------------------------
	sizeofServer = sizeof(server);

	pid_t PIDserver;
	//budeme komunikovat s vice klienty soucasne
	//DODELAT UKONCENI VSEHO PRI SIGTERM, prekontrolovat exity a returny

	buffer_t buffer[BUFFSIZE];
	buffer_t response_buffer[BUFFSIZE];
	memset(buffer, 0, BUFFSIZE);
	memset(response_buffer, 0, BUFFSIZE);

	while (true)
	{		
		socklen_t sizeofClient = sizeof (client);
		
		int received_data;
		received_data = recvfrom (ipv4_socket,buffer, sizeof(buffer_t) * BUFFSIZE,0,(struct sockaddr *) &client,&sizeofClient);

		DNS_SERVER.decode(buffer);
		DNS_SERVER.reply(response_buffer);
	
		//odesilame upraveny buffer s odpovedi zpet klientovi
		sendto(ipv4_socket, response_buffer, sizeof(buffer_t) * DNS_SERVER.tracker,0,(struct sockaddr *) &client, sizeofClient);

	}

	//uzavreme socket
	if (close(ipv4_socket) < 0)
	{
		cerr << "## ERROR ## Could not close socket." << endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;

}

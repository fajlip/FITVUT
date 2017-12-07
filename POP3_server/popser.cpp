/*
	Autor: Brezna Filip
	Login: xbrezn00
	Project name: popser (POP3 server)
*/	

#include <iostream> //standardni knihovna
#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h> //sockaddr_in
#include <signal.h>
#include <unistd.h> //getpid
#include <time.h> 
#include <thread> 
#include <fcntl.h> //fnctl funkce
#include <vector>

#include "md5.h"
//moje hlavickove soubory
#include "popser_class.h"

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define EXIT_GET_PASS 2
#define	EXIT_QUIT 3
#define EXIT_APOP 4	
//nastavitelna hodnota fronty cekajicich socketu
#define QUEUE_SIZE 128
//maximalni velikost zpravy
#define BUFFSIZE 1024

using namespace std;

//globalni pole pro ukladani socketu
vector<int> socket_array;

//kontrola portu
int portCheck (string portStr)
{
	char * pEnd;
	int result = strtol (portStr.c_str(), &pEnd, 10);

	//povolena cisla portu
	if (*pEnd != '\0' || result < 1 || result > 65535)
	{
		cerr << "## ERROR ## Invalid port number." << endl;
		exit (EXIT_FAILURE);
	}

	return result;
}
/*
Použitie:
./popser [-h] [-a PATH] [-c] [-p PORT] [-d PATH] [-r]
h (help) - voliteľný parameter, pri jeho zadaní sa vypíše nápoveda a program sa ukončí
a (auth file) - cesta k súboru s prihlasovacími údajmi
c (clear pass) - voliteľný parameter, pri zadaní server akceptuje autentizačnú metódu, ktorá prenáša heslo v nešifrovanej podobe (inak prijíma iba heslá v šifrovanej podobe - hash)
p (port) - číslo portu na ktorom bude bežať server
d (directory) - cesta do zložky Maildir (napr. ~/Maildir/)
r (reset) - server vymaže všetky svoje pomocné súbory a emaily z Maildir adresárovej štruktúry vráti do stavu, ako keby proces popser nebol nikdy spustený (netýka sa časových pečiatok, iba názvov a umiestnení súborov) (týka sa to len emailov, ktoré sa v adresárovej štruktúre nachádzajú).
*/

int port;
bool r_set = false;
bool the_end = false;


//funkce pro kontrolu vstupnich argumentu
void checkArguments(int argc, char** argv, pop3_server &POP3_SERVER)
{
	string temp;
	//pro kontrolu, zda neni nektery parametr zadan vickrat
	bool a_set = false, p_set = false, d_set = false;

	//nebyly zadany zadne argumenty.
	if (argc == 1)
	{
		cerr << "## ERROR ## No arguments. You can use -h for help." << endl;
		exit (EXIT_FAILURE);
	}

	//bylo zadano moc argumentu.
	else if (argc > 9)
	{
		cerr << "## ERROR ## Too many arguments. You can use -h for help." << endl;
		exit (EXIT_FAILURE);
	}

	//byl spravne zadan help
	else if (string(argv[1]) == "-h")
	{
		cout << "This is help for: " << string(argv[0]) << endl << "./popser [-h] [-a PATH] [-c] [-p PORT] [-d PATH] [-r]" << endl;
		cout << endl;
		cout << "-a (auth file) - cesta k souboru s prihlasovacimi udaji" << endl;
		cout << "-c (clear pass) - volitelný parameter, pri zadaní server akceptuje autentizacni metodu, ktera prenasi heslo v nesifrovane podobe (jinak prijima jen hesla v sifrovane podobe - hash)" << endl;
 		cout << "-p (port) - cislo portu na ktorem bude bezet server" << endl;
		cout << "-d (directory) - cesta do slozky Maildir (napr. ~/Maildir/)" << endl;
		cout << "-r (reset) - server vymaze vsechny svoje pomocne soubory a emaily z Maildir adresarove struktury vrati do stavu, jako kdyby proces popser nebyl nikdy spusteny (netyka se casovych znacek, jen nazvu a umistneni suborov) (tyka sa to jen emailu, ktere se v adresarove strukture nachazeji)." << endl;

		exit (EXIT_SUCCESS);
	}

	for(int i = 1; i < argc; i++)
	{
		//a (auth file)
		if (string(argv[i]) == "-a")
		{
			if (a_set)
			{
				cerr << "## ERROR ## Auth argument was used more than once." << endl;
				exit (EXIT_FAILURE);
			}

			i += 1;
			if (i == argc)
			{
				cerr << "## ERROR ## Auth argument has no value." << endl;
				exit (EXIT_FAILURE);
			}


			POP3_SERVER.file_path = string(argv[i]);
			a_set = true;
		}

		//c (clear pass)
		else if (string(argv[i]) == "-c")
		{
			if (POP3_SERVER.c_set)
			{
				cerr << "## ERROR ## Clear pass argument was used more than once." << endl;
				exit (EXIT_FAILURE);
			}

			POP3_SERVER.c_set = true;
		}	
			

		//p (port)
		else if (string(argv[i]) == "-p")
		{
			if (p_set)
			{
				cerr << "## ERROR ## Port argument was used more than once." << endl;
				exit (EXIT_FAILURE);
			}

			i += 1;
			if (i == argc)
			{
				cerr << "## ERROR ## Port argument has no value." << endl;
				exit (EXIT_FAILURE);
			}

			port = portCheck(argv[i]);
			p_set = true;
		}

		//d (directory)
		else if (string(argv[i]) == "-d")
		{
			if (d_set)
			{
				cerr << "## ERROR ## Directory argument was used more than once." << endl;
				exit (EXIT_FAILURE);
			}

			i += 1;
			if (i == argc)
			{
				cerr << "## ERROR ## Directory argument has no value." << endl;
				exit (EXIT_FAILURE);
			}

			temp = string(argv[i]);

			if (temp.back() != '/')
				temp.append("/");

			POP3_SERVER.directory_path = temp;

			//zkontrolujeme zda je adresa slozky platna
			//directoryPathCheck(directory_path);
			d_set = true;
		}


		//r (reset)
		else if (string(argv[i]) == "-r")
		{
			if (r_set)
			{
				cerr << "## ERROR ## Reset argument was used more than once." << endl;
				exit (EXIT_FAILURE);
			}

			r_set = true;
		}

		else
		{
			cerr << "## ERROR ## Arguments are not valid. You can use -h for help." << endl;
			exit (EXIT_FAILURE);
		}	

	}

}

//funkce zajistuje veskerou komunikaci mezi klientem a serverem
bool clientCommunicationHandler(char * hostname, int accepted_sock, pop3_server *myPOP3_SERVER)
{
	pop3_server &POP3_SERVER = (*myPOP3_SERVER);
	struct sockaddr_in client;
	socklen_t sizeofClient = sizeof (client);

	int received_data, result, select_ret_value;
	char entry_buffer[BUFFSIZE];
	char response_buffer[BUFFSIZE];
	//pomocne stringy pro prevod na pole uvedene o 2 radky vyse
	string temp_response_buffer, temp_entry_buffer;
	
	//temp slouzi k ukladani docasnych stringu nez dojde k jejich odeslani
	string temp;

	//musime vytvorit casovou znamku, ktera bude poslana klientovi
	//ziskame cislo procesu
	pid_t processID = getpid();
	
	//nyni potrebujeme hodnotu promenne Time
	time_t timer;
	struct tm year_2000 = {0};

	//nastavime na rok 2000. 1 leden
	year_2000.tm_hour = 0;   year_2000.tm_min = 0; year_2000.tm_sec = 0;
	year_2000.tm_year = 100; year_2000.tm_mon = 0; year_2000.tm_mday = 1;

	time(&timer);  /* get current time; same as: timer = time(NULL)  */

	//pocet vterin co ubehlo od roku 2000
	double clock_time = difftime(timer,mktime(&year_2000));


	//pro funkci select
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(accepted_sock, &readfds);
	struct timeval client_timeout;

	//reset timeru na timeout
	client_timeout.tv_sec = 600;
	client_timeout.tv_usec = 0;


	//The AUTHORIZATION State
	while (true) 
	{
		//vycistime buffery
		memset(entry_buffer, 0, BUFFSIZE);
		memset(response_buffer, 0, BUFFSIZE);


		//casova znamka pro uvitaci hlasku, vyuziva se pro vypocet hashe pro APOP
		POP3_SERVER.time_stamp = "<" + to_string(processID) + "." + to_string((int) clock_time) +  "@" + temp.assign(hostname) + ">";

		//slouzi pro response_buffer
		temp = "+OK POP3 server is ready. Go on fast, I don't have no time for no monkey business. " + POP3_SERVER.time_stamp + "\r\n";
		
		//prekopirujeme pomocny string temp do response_buffer	
		strcpy(response_buffer, temp.c_str());

		sendto(accepted_sock, response_buffer, temp.length(), 0,(struct sockaddr *) &client, sizeofClient);
		
		select_ret_value = select (accepted_sock + 1, &readfds, NULL, NULL, &client_timeout);

		//timeout vyprsel
		if (select_ret_value == 0)
		{
			//uzavreme socket s kterym pracuje klient
			if (close(accepted_sock) < 0)
				cerr << "## ERROR ## Could not close socket accepted_sock." << endl;

			//zamek zase odemkneme, muze pracovat dalsi uzivatel
			POP3_SERVER.access_locker.unlock();
			return EXIT_FAILURE;
		}

		//doslo k chybe
		else if (select_ret_value < 0)
		{
			cerr << "## ERROR ## Function select() did not worked properly." << endl;
			//uzavreme socket s kterym pracuje klient
			if (close(accepted_sock) < 0)
				cerr << "## ERROR ## Could not close socket accepted_sock." << endl;

			//zamek zase odemkneme, muze pracovat dalsi uzivatel
			POP3_SERVER.access_locker.unlock();
			return EXIT_FAILURE;
		}	

		//prekontrolovat navratovou adres recvfrom		
		received_data = recvfrom (accepted_sock, entry_buffer, BUFFSIZE, 0, (struct sockaddr *) &client, &sizeofClient);
		
		//reset timeru na timeout
		client_timeout.tv_sec = 600;
		client_timeout.tv_usec = 0;

		//recieve se nepovedl nebo uz klient nic poslat nechce
		if (received_data < 1)
		{
			if (!the_end)
				cerr << "## ERROR ## Data recieve from client was unsuccessful." << endl;
			//uzavreme socket s kterym pracuje klient
			if (close(accepted_sock) < 0)
				cerr << "## ERROR ## Could not close socket accepted_sock." << endl;

			//zamek zase odemkneme, muze pracovat dalsi uzivatel
			POP3_SERVER.access_locker.unlock();
			return EXIT_FAILURE;
		}
		
		result = POP3_SERVER.authorization(temp_entry_buffer.assign(entry_buffer), temp_response_buffer.assign(response_buffer));

		//vynulujeme buffery
		memset(entry_buffer, 0, BUFFSIZE);
		memset(response_buffer, 0, BUFFSIZE);
		//vratime pomocny string zpet do bufferu
		strcpy(response_buffer, temp_response_buffer.c_str());

		sendto(accepted_sock, response_buffer, temp_response_buffer.length(), 0,(struct sockaddr *) &client, sizeofClient);
	
		if (result == EXIT_QUIT)
		{
			//uzavreme socket s kterym pracuje klient
			if (close(accepted_sock) < 0)
			{
				cerr << "## ERROR ## Could not close socket accepted_sock." << endl;
				//zamek zase odemkneme, muze pracovat dalsi uzivatel
				POP3_SERVER.access_locker.unlock();
				return EXIT_FAILURE;
			}

			//prace konci
			//zamek zase odemkneme, muze pracovat dalsi uzivatel
			POP3_SERVER.access_locker.unlock();
			return EXIT_SUCCESS;

		}

		//user je v poradku zadejme heslo
		else if (result == EXIT_GET_PASS)
		{
			//reset timeru na timeout
			//client_timeout.tv_sec = 600;
			//client_timeout.tv_usec = 0;
			select_ret_value = select (accepted_sock + 1, &readfds, NULL, NULL, &client_timeout);

			//timeout vyprsel
			if (select_ret_value == 0)
			{
				//uzavreme socket s kterym pracuje klient
				if (close(accepted_sock) < 0)
					cerr << "## ERROR ## Could not close socket accepted_sock." << endl;

				//zamek zase odemkneme, muze pracovat dalsi uzivatel
				POP3_SERVER.access_locker.unlock();
				return EXIT_FAILURE;
			}

			//doslo k chybe
			else if (select_ret_value < 0)
			{
				cerr << "## ERROR ## Function select() did not worked properly." << endl;
				//uzavreme socket s kterym pracuje klient
				if (close(accepted_sock) < 0)
					cerr << "## ERROR ## Could not close socket accepted_sock." << endl;

				//zamek zase odemkneme, muze pracovat dalsi uzivatel
				POP3_SERVER.access_locker.unlock();
				return EXIT_FAILURE;
			}	

			//prijememe od klienta dalsi zpravu
			received_data = recvfrom (accepted_sock, entry_buffer, BUFFSIZE, 0, (struct sockaddr *) &client, &sizeofClient);

			//reset timeru na timeout
			client_timeout.tv_sec = 600;
			client_timeout.tv_usec = 0;

			//recieve se nepovedl nebo uz klient nic poslat nechce
			if (received_data < 1)
			{
				if (!the_end)
					cerr << "## ERROR ## Data recieve from client was unsuccessful." << endl;
				//uzavreme socket s kterym pracuje klient
				if (close(accepted_sock) < 0)
					cerr << "## ERROR ## Could not close socket accepted_sock." << endl;

				//zamek zase odemkneme, muze pracovat dalsi uzivatel
				POP3_SERVER.access_locker.unlock();
				return EXIT_FAILURE;
			}

			//funkce na overeni zadaneho hesla 
			result = POP3_SERVER.getPassword(temp_entry_buffer.assign(entry_buffer), temp_response_buffer.assign(response_buffer));
			
			if (result == EXIT_QUIT)
			{
				//uzavreme socket s kterym pracuje klient
				if (close(accepted_sock) < 0)
				{
					cerr << "## ERROR ## Could not close socket accepted_sock." << endl;
					//zamek zase odemkneme, muze pracovat dalsi uzivatel
					POP3_SERVER.access_locker.unlock();
					return EXIT_FAILURE;
				}
			

				//prace konci
				//zamek zase odemkneme, muze pracovat dalsi uzivatel
				POP3_SERVER.access_locker.unlock();
				return EXIT_SUCCESS;
			}

			//vynulujeme buffery
			memset(entry_buffer, 0, BUFFSIZE);
			memset(response_buffer, 0, BUFFSIZE);
			
			//vratime pomocny string zpet do bufferu
			strcpy(response_buffer, temp_response_buffer.c_str());
			
			sendto(accepted_sock, response_buffer, temp_response_buffer.length(),0,(struct sockaddr *) &client, sizeofClient);

			//neuspesny konec, vratme se na zacatek
			if (result == EXIT_FAILURE)
				continue;

			//pokud bylo zadavani uspesne, vyskocime z cyklu a pujdeme do dalsiho
			//jiz budeme delat transakcni cast
			if (result == EXIT_SUCCESS)
				break;

		}

		else if (result == EXIT_APOP)
			break;	
		
		//neuspesny konec, vratme se na zacatek
		else if (result == EXIT_FAILURE)
			continue;

	}

	//TRANSACTION STATE
	while (true)
	{
		//vycistime buffery
		memset(entry_buffer, 0, BUFFSIZE);
		memset(response_buffer, 0, BUFFSIZE);

		//reset timeru na timeout
		//client_timeout.tv_sec = 600;
		//client_timeout.tv_usec = 0;
		select_ret_value = select (accepted_sock + 1, &readfds, NULL, NULL, &client_timeout);

		//timeout vyprsel
		if (select_ret_value == 0)
		{
			//uzavreme socket s kterym pracuje klient
			if (close(accepted_sock) < 0)
				cerr << "## ERROR ## Could not close socket accepted_sock." << endl;

			//zamek zase odemkneme, muze pracovat dalsi uzivatel
			POP3_SERVER.access_locker.unlock();
			return EXIT_FAILURE;
		}

		//doslo k chybe
		else if (select_ret_value < 0)
		{
			cerr << "## ERROR ## Function select() did not worked properly." << endl;
			//uzavreme socket s kterym pracuje klient
			if (close(accepted_sock) < 0)
				cerr << "## ERROR ## Could not close socket accepted_sock." << endl;

			//zamek zase odemkneme, muze pracovat dalsi uzivatel
			POP3_SERVER.access_locker.unlock();
			return EXIT_FAILURE;
		}	


		//prekontrolovat navratovou adres recvfrom		
		received_data = recvfrom (accepted_sock, entry_buffer, BUFFSIZE, 0, (struct sockaddr *) &client, &sizeofClient);
		
		//reset timeru na timeout
		client_timeout.tv_sec = 600;
		client_timeout.tv_usec = 0;


		//prekontorlujeme zda byl recvfrom uspesny
		if (received_data < 1)
		{
			if (!the_end)
				cerr << "## ERROR ## Data recieve from client was unsuccessful." << endl;
			//uzavreme socket s kterym pracuje klient
			if (close(accepted_sock) < 0)
				cerr << "## ERROR ## Could not close socket accepted_sock." << endl;
			
			//zamek zase odemkneme, muze pracovat dalsi uzivatel
			POP3_SERVER.access_locker.unlock();
			return EXIT_FAILURE;
		}

		//spustime funkci, ktera vykonava TRANSAKCNI cast
		result = POP3_SERVER.transaction(temp_entry_buffer.assign(entry_buffer), temp_response_buffer.assign(response_buffer));

		//klient ukoncil spojeni
		if (result == EXIT_QUIT)
		{
			//klient si preje skoncit, smazeme zpravy oznacene jako delete
			POP3_SERVER.realMessageDelete(temp_response_buffer.assign(response_buffer));
			//vratime pomocny string zpet do bufferu
			strcpy(response_buffer, temp_response_buffer.c_str());
			
			//odesleme ziskanou odpoved klientovi
			sendto(accepted_sock, response_buffer, temp_response_buffer.length(),0,(struct sockaddr *) &client, sizeofClient);
			
			//uzavreme socket s kterym pracuje klient
			if (close(accepted_sock) < 0)
			{
				cerr << "## ERROR ## Could not close socket accepted_sock." << endl;
				//zamek zase odemkneme, muze pracovat dalsi uzivatel
				POP3_SERVER.access_locker.unlock();
				return EXIT_FAILURE;
			}

			//prace konci
			//zamek zase odemkneme, muze pracovat dalsi uzivatel
			POP3_SERVER.access_locker.unlock();
			return EXIT_SUCCESS;
		}	

		//pokud vse probehlo v poradku a nebo naopak ani nemuselo, proces je mozne opakovat
		else
		{	
			//vratime pomocny string zpet do bufferu
			strcpy(response_buffer, temp_response_buffer.c_str());
			
			//odesleme ziskanou odpoved klientovi
			sendto(accepted_sock, response_buffer, temp_response_buffer.length(),0,(struct sockaddr *) &client, sizeofClient);
		}

	}

	return EXIT_SUCCESS;
}


//zajisti uzavreni socketu pri prichodu ctrl c 
void SIGINT_handler(int signal_number)
{
	for (unsigned i = 0; i < socket_array.size(); ++i)
	{
			//uzavreme sockety
			if (close(socket_array.at(i)) < 0)
				cerr << "## ERROR ## Could not close socket number" + to_string(socket_array.at(i)) + " ." << endl;
			
	}
	//aby se dobre zarovnalo v terminalu
	cerr << endl;
	the_end = true;
	exit(signal_number); 
}


int main (int argc, char** argv)
{

	//nastavime sigint signal. Tedy handle pro ctrl c ukonceni serveru
	signal (SIGINT, SIGINT_handler);

	pop3_server POP3_SERVER;

	checkArguments(argc, argv, POP3_SERVER);

	if (r_set)
	{
		POP3_SERVER.resetParameter(argv);
		if (argc == 2)
			return EXIT_SUCCESS;
	}	


	//prepiseme soubory ze slozky new v maildir do slozky cur v maildir
	POP3_SERVER.newToCur(argv);


	int ipv4_socket;
	
	//vytvorime socket; AF_INET = IPv4; SOCK_STREAM = TCP komunikace;  0 je označení defaultního protokolu
	ipv4_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (ipv4_socket < 0)
	{
		cerr << "## ERROR ## Broken server 'ipv4_socket' socket." << endl;
		return EXIT_FAILURE;
	}

	//pridame socket do pole
	socket_array.push_back(ipv4_socket);

	//ze skolnich slajdu, prepnuti socketu do neblokujiciho rezimu
	int flags = fcntl(ipv4_socket, F_GETFL, 0);
	
	if ( (fcntl(ipv4_socket, F_SETFL, flags | O_NONBLOCK)) < 0)
		cerr << "## ERROR ## Non block socket was not created, FCNTL failed." << endl;
		//return?

	//ziskame hostname, bude stale stejny proto uz v mainu (poslouzi pro casovou znamku)
	char hostname[1024];
	hostname[1023] = '\0';
	gethostname(hostname, 1023);


	//naplneni struktury sockaddr_in
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	//host interface address in network byte order
	server.sin_addr.s_addr = INADDR_ANY;

	socklen_t sizeofServer = sizeof (server);


	//bindne jmeno na socket
	if (bind(ipv4_socket, (struct sockaddr *) &server, sizeofServer) < 0)
	{
		cerr << "## ERROR ## Bind was unsuccessful. Port not available." << endl;
		return EXIT_FAILURE;
	}	

	//oznaci socket za pasivni a vlozi ho do fronty
	if (listen(ipv4_socket, QUEUE_SIZE) < 0)
	{
		cerr << "## ERROR ## Listen was unsuccessful." << endl;
		return EXIT_FAILURE;
	}

	std::thread thread_id;
	int accepted_sock;
	//sigint???
	while (true)
	{
		//vyjme ze fronty naslouchajicich socketu nasledujici v poradi a vytvori novou kopii puvodniho socketu,
		//ale ne v naslouchacim stavu	
		while ( (accepted_sock = accept(ipv4_socket, (struct sockaddr *) &server, &sizeofServer)) > 0)
		{
			if (accepted_sock < 0)
			{
				cerr << "## ERROR ## accept was unsuccessful." << endl;
				return EXIT_FAILURE;		
			}

			//pridame socket do pole
			socket_array.push_back(accepted_sock);

			//ze skolnich slajdu, prepnuti socketu do neblokujiciho rezimu
			flags = fcntl(accepted_sock, F_GETFL, 0);
			
			if ( (fcntl(accepted_sock, F_SETFL, flags | O_NONBLOCK)) < 0)
				cerr << "## ERROR ## Non block socket was not created, FCNTL failed." << endl;

			//vyuziti vlaken. Zavola se funkce clientCommunicationHandler jako nove vlakno
			thread_id = std::thread(clientCommunicationHandler, hostname, accepted_sock, &POP3_SERVER);
			//vlakno se stane nezavislym
			thread_id.detach();
			
		}
	}
	
	return EXIT_SUCCESS;
}

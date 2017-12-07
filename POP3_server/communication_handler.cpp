#include <iostream>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <dirent.h> //prace se slozkou
#include <sys/stat.h> //zjisteni velikosti souboru
#include <sys/types.h>
#include <vector>
#include <mutex>
#include <algorithm>
#include <locale> //povolene?

#include "md5.h"
#include "popser_class.h"


#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define EXIT_GET_PASS 2
#define	EXIT_QUIT 3
#define EXIT_APOP 4

#define STAT_CHOSEN 0
#define LIST_CHOSEN 1
#define UIDL_CHOSEN 2
#define TOP_CHOSEN 3
#define RETR_CHOSEN 4

using namespace std;

std::vector<int> message_sizes;

//prekontrolujeme zda existuje takovy uzivatel
int pop3_server::checkLoginFile(string &response_buffer)
{
		FILE *login_info;

		//otevřeme soubor pro cteni
		//string filename = file_path+"prihlasovaci_udaje";

		login_info = fopen (file_path.c_str(), "r");
		if (login_info == NULL)
		{
			cerr << "## ERROR ## File with login informations cannot be open." << endl;
			exit (EXIT_FAILURE);
		}

		bool pass_expected = false;

		char read_char;
		vector<char> line;
		line.reserve(50);

		string temp;

		while ((read_char = fgetc(login_info)) != EOF)
		{ 

			line.push_back(read_char);
			
			//if EOL
			if (read_char == '\n')
			{
				//odstranime z konce vectoru znak noveho radku
				line.pop_back();
				
				temp.assign(line.begin(), line.end());

				if (pass_expected)
				{
					for (unsigned int i = 0; i < line.size(); ++i)
					{
						//rovnou si ulozime ocekavane heslo, at ho pozdeji jen overime
						if ((line.at(i) == '=') && (line.at(i+1) == ' '))
							pass.assign(&line.at(i+2), line.size()-i-2);
						
					}

					break;
				}

				//uzivatel byl nalezen
				else if (temp == "username = " + user)
				{
					user_found = true;
					pass_expected = true;
				}

				line.clear();

			}	
		}

		fclose(login_info);

		//budeme chtit heslo i pokud uzivatel neexistuje, ochrana proti brute force
		response_buffer = "+OK now I need password.\r\n";
		//vratim EXIT_GET_PASS, abych pak mohl v hlavnim cpp souboru indetifikovat USER command a nasleduje heslo
		return EXIT_GET_PASS;

}

//inline funkce, ktera odstrani bile znaky na konci retezce 
static inline void rtrim(std::string & s) {
    s.erase( s.find_last_not_of(" \n\r\t") + 1);
}

//funkce na overeni clientem iniciovaneho uzivatele a hesla
int pop3_server::authorization (string &entry_buffer, string &response_buffer)
{
	//odstraneni CRLF v entry bufferu; 
	rtrim(entry_buffer);
	
	string temp;

	//prirad do temp, prvni 4 znaky vstupniho bufferu; ocekcavame USER, QUIT nebo APOP
	temp = entry_buffer.substr(0,4);

	//prevedeme na velka, nemuzeme prevadet cely string, heslo a jmeno je case sensitive 
	std::transform(temp.begin(), temp.end(), temp.begin(), ::toupper);

	//nemuzeme prevest cely string na velka pismena, protoze heslo a jmeno je case sensitive
	if (temp == "USER")
	{
		//pamametr c nebyl zadan, nemuzeme se autentizovat jinak nez sifrovanou metodou
		//nefunguje
		if (!c_set)
		{
			response_buffer = "-ERR Parameter -c not set, which means you cannot use USER command for clear authorization.\r\n";
			return EXIT_FAILURE;
		}

		//USER + mezera a pote nasleduje username, ten prirazujeme do string promenne
		if (entry_buffer.length() > 4)
			user = entry_buffer.substr(5,entry_buffer.length()-5);

		else
		{
			response_buffer = "-ERR USER command expected user value and that was not defined.\r\n";
			return EXIT_FAILURE;
		}


		int result = checkLoginFile(response_buffer);
		return result;
	}


	//sifrovane prihlasovani
	else if (temp == "APOP")
	{
		//kontrola c prepinace
		if (c_set)
		{
			response_buffer = "-ERR Parameter -c set, which means you cannot use APOP command for authorization.\r\n";
			return EXIT_FAILURE;
		}

		//APOP + mezera + user + mezera a pote nasleduje hash, ten prirazujeme do string promenne
		//5 je delka slova APOP + mezera
		size_t pos = entry_buffer.find_first_of(' ', 5);

		if (pos != std::string::npos)
			user = entry_buffer.substr(5,pos-5);

		else
		{
			response_buffer = "-ERR APOP command expected user and then hash value and that was not defined.\r\n";
			return EXIT_FAILURE;
		}

		if (user.size() == 0)
		{
			response_buffer = "-ERR APOP hash is missing. Input one next time or use USER method.\r\n";
			return EXIT_FAILURE;
		}

		
		string hash_client = entry_buffer.substr(pos+1, entry_buffer.length()-pos);

		if (checkLoginFile(response_buffer) == EXIT_FAILURE)
			return EXIT_FAILURE;

		string forHashControl = time_stamp + pass;
		string hash_server = md5(forHashControl);

		if (hash_client == hash_server)
		{
			//spocitame si pocet zprav a celkovou velikost
			int number_messages = 0, number_octets = 0;
			number_messages = message_sizes.size()-1;

			for (unsigned i = 0; i < message_sizes.size(); ++i)
				number_octets += message_sizes.at(i);

			response_buffer = "+OK APOP hash is correct. User has " + to_string(number_messages) + " messages (" + to_string(number_octets) + " octets).\r\n";
			
			//pokusime se ziskat pristup k autentizaci
			if (!access_locker.try_lock())
			{
				response_buffer = "-ERR Someone else is working with Maildir right now.\r\n";	
				return EXIT_FAILURE;
			}

			return EXIT_APOP;
		}	

		else
		{
			response_buffer = "-ERR APOP Hash sequesnce is not correct.\r\n";	
			return EXIT_FAILURE;
		}	

		//warning
		return EXIT_APOP;
	}


	else if (temp == "QUIT")
	{
		response_buffer = "+OK POP3 server processing your QUIT command.\r\n";
		return EXIT_QUIT;
	}

	else
	{
		response_buffer = "-ERR Wrong command. Try again, do not give up, but if you're weak, use -h.\r\n";
		return EXIT_FAILURE;
	}


}

//porovna zadane heslo s heslem spravnym
int pop3_server::getPassword(string &entry_buffer, string &response_buffer)
{
	//odstranime mezery na konci stringu
	rtrim(entry_buffer);
	
	//prirad do temp, prvni 4 znaky vstupniho bufferu, ocekavame PASS
	string temp = entry_buffer.substr(0,4);

	//prevedeme na velka, nemuzeme prevadet cely string, heslo a jmeno je case sensitive 
	std::transform(temp.begin(), temp.end(), temp.begin(), ::toupper);


	if (temp == "PASS")
	{
		if (entry_buffer.length() > 4)
			//PASS + mezera a pote nasleduje heslo, to prirazujeme do string promenne
			temp = entry_buffer.substr(5,entry_buffer.length()-5);
		
		else
		{
			response_buffer = "-ERR PASS command expected pass value and that was not defined.\r\n";
			return EXIT_FAILURE;
		}

		//ve funkci authorization jsme si ulozili ocekavane heslo do pop3_server.pass, nyni porovname
		if ((pass == temp) && (user_found == true))
		{
			//spocitame si pocet zprav a celkovou velikost
			int number_messages = 0, number_octets = 0;
			number_messages = message_sizes.size()-1;

			for (unsigned i = 0; i < message_sizes.size(); ++i)
				number_octets += message_sizes.at(i);
			//musim zde vypsat pocet zprav a takovy veci

			response_buffer = "+OK POP3 password is correct. User has " + to_string(number_messages) + " messages (" + to_string(number_octets) + " octets).\r\n";
			
			//pokusime se ziskat pristup k autentizaci
			if (!access_locker.try_lock())
			{
				response_buffer = "-ERR Someone else is working with Maildir right now.\r\n";	
				return EXIT_FAILURE;
			}	
			return EXIT_SUCCESS;
	
		}

		//nebylo zadano spravne heslo. To je spatne
		else
		{
			response_buffer = "-ERR Password or user incorrect, you shall not pass.\r\n";
			return EXIT_FAILURE;			
		}

	}

	else if (temp == "QUIT")
	{
		response_buffer = "+OK POP3 server processing your QUIT command.\r\n";
		return EXIT_QUIT;
	}

	else
	{
		response_buffer = "-ERR Wrong command. Try again, do not give up, but if you're weak, use -h.\r\n";
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int pop3_server::transaction (string &entry_buffer, string &response_buffer)
{
	int result;
	//odstraneni CRLF v entry bufferu
	rtrim (entry_buffer);
	//vse na velka pismena
	std::transform(entry_buffer.begin(), entry_buffer.end(), entry_buffer.begin(), ::toupper);

	string temp;

	//prirad do temp, prvni 4 znaky vstupniho bufferu; ocekcavame USER, QUIT nebo APOP
	temp = entry_buffer.substr(0,4);


	//entry_buffer == "STAT" ?????????
	if (temp == "STAT")
		return(listOrStatOrUidl(response_buffer, STAT_CHOSEN));

	//klient si preje ukoncit komunikaci
	else if (temp == "QUIT")
	{
		return EXIT_QUIT;
	}

	else if (temp == "LIST")
	{
		//tedy pokud bylo za LIST neco pridano
		if (entry_buffer.length() > 4)
		{
			//LIST + mezera a pote MUZE nasledovat konkretni vyber zpravy
			temp = entry_buffer.substr(5,entry_buffer.length()-5);

			char * p;
   			int list_message = strtol(temp.c_str(), &p, 10);

   			//nebylo zadano cislo
   			if (*p != 0)
   			{
   				response_buffer = "-ERR Message number " + temp + " is not correct value. LIST cannot be performed.\r\n";
   				return EXIT_FAILURE;
   			}

			result = listOrStatOrUidl(response_buffer, LIST_CHOSEN, list_message);
			
		}

		else
			result = listOrStatOrUidl(response_buffer, LIST_CHOSEN);

		return result;
	}

	else if (temp == "RETR")
	{
		//tedy pokud bylo za DELE pridano cislo zpravy
		if (entry_buffer.length() > 4)
		{

			temp = entry_buffer.substr(5,entry_buffer.length()-5);

			char * p;
   			int retrieve_mssg_number = strtol(temp.c_str(), &p, 10);

   			//nebylo zadano cislo
   			if (*p != 0)
   			{
   				response_buffer = "-ERR Message number " + temp + " is not correct value. RETR cannot be performed.\r\n";
   				return EXIT_FAILURE;
   			}
		
			return(retrieveOrTopMssg(response_buffer, RETR_CHOSEN, retrieve_mssg_number));

		}

		else
		{
			response_buffer = "-ERR RETR command expects number of message that you want to mark as deleted and that was not specified.\r\n";
			return EXIT_FAILURE;
		}


	}

	
	else if ((temp == "TOP") || (temp == "TOP "))
	{
		string msg_numb_temp, number_of_lines_temp;
		
		size_t pos = entry_buffer.find(' ', 0);
		size_t pos2 = entry_buffer.find(' ', pos+1);

		if (pos != std::string::npos)
		{
			if (pos2 != std::string::npos)
			{
				msg_numb_temp = entry_buffer.substr(pos+1, pos2-1-pos);
				number_of_lines_temp = entry_buffer.substr(pos2+1, entry_buffer.length()-pos2-1);
			}

			else	
				msg_numb_temp = entry_buffer.substr(pos+1, entry_buffer.length()-pos-1);
		}	

		//tedy pokud bylo za TOP pridano cislo zpravy
		if (msg_numb_temp.size() != 0)
		{
			char * p;
   			int top_mssg_number = strtol(msg_numb_temp.c_str(), &p, 10);

   			//nebylo zadano cislo
   			if (*p != 0)
   			{
   				response_buffer = "-ERR Message number " + msg_numb_temp + " is not correct value. TOP cannot be performed.\r\n";
   				return EXIT_FAILURE;
   			}

			//tedy pokud bylo za TOP pridano cislo zpravy a pocet radku
   			if (number_of_lines_temp.size() != 0)
   			{
	   			int number_of_lines = strtol(number_of_lines_temp.c_str(), &p, 10);

	   			//nebylo zadano cislo
	   			if (*p != 0)
	   			{
	   				response_buffer = "-ERR Lines number " + number_of_lines_temp + " is not correct value. TOP cannot be performed.\r\n";
	   				return EXIT_FAILURE;
	   			}
			
			
				return(retrieveOrTopMssg(response_buffer, TOP_CHOSEN, top_mssg_number, number_of_lines));
   			}

   			else
   			{
				response_buffer = "-ERR TOP command expects number of message that you want to send and that was not specified.\r\n";
				return EXIT_FAILURE;
			}
		}

		else
		{
   			response_buffer = "-ERR TOP command expects number of message that you want to send and that was not specified.\r\n";
   			return EXIT_FAILURE;
   		}

	}


	else if (temp == "UIDL")
	{
		//tedy pokud bylo za UIDL neco pridano
		if (entry_buffer.length() > 4)
		{

			temp = entry_buffer.substr(5,entry_buffer.length()-5);

			char * p;
   			int uidl_mssg_number = strtol(temp.c_str(), &p, 10);

   			//nebylo zadano cislo
   			if (*p != 0)
   			{
   				response_buffer = "-ERR Message number " + temp + " is not correct value. UIDL cannot be performed.\r\n";
   				return EXIT_FAILURE;
   			}
		
		
			return(listOrStatOrUidl(response_buffer, UIDL_CHOSEN, uidl_mssg_number));
		}

		else
			return(listOrStatOrUidl(response_buffer, UIDL_CHOSEN));

	}

	else if (temp == "DELE")
	{

		//tedy pokud bylo za DELE neco pridano
		if (entry_buffer.length() > 4)
		{

			temp = entry_buffer.substr(5,entry_buffer.length()-5);

			char * p;
   			int delete_mssg_number = strtol(temp.c_str(), &p, 10);

   			//nebylo zadano cislo
   			if (*p != 0)
   			{
   				response_buffer = "-ERR Message number " + temp + " is not correct value. LIST cannot be performed.\r\n";
   				return EXIT_FAILURE;
   			}
		
		
			return(deleteMssg(delete_mssg_number, response_buffer));
		}

		else
		{
			response_buffer = "-ERR DELE command expects number of message that you want to mark as deleted and that was not specified.\r\n";
			return EXIT_FAILURE;
		}


	}

	//funkce No operation; odpovi jako +OK. Nic vic
	else if (temp == "NOOP")
	{
		response_buffer = "+OK\r\n";
		return EXIT_SUCCESS;
	}

	else if (temp == "RSET")
		return(unmarkDeletedMssgs(response_buffer));

	else
	{
		response_buffer = "-ERR Wrong command. Try again, do not give up, but if you're weak, use -h.\r\n";
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//pokud nebude do funkce vlozen posledni argument pro list message, automaticky bude roven 0
//jedna se tedy o voliteny argument
//funkce bude provadet vypis LIST nebo STAT podle zadaneho prepinace
int pop3_server::listOrStatOrUidl(string &response_buffer, int list_stat_uidl, int list_uidl_message)
{
	DIR *mydirectory;
	struct dirent *entry; 

	// + "Mailbox/cur"
	string path_to_files = directory_path + "cur/";
	if ( (mydirectory = opendir(path_to_files.c_str()) ) != NULL)
	{

        string temp;

        int number_messages = 0, deleted_messages = 0;

        //prochazime soubory v otevrene slozce
		while ( (entry = readdir (mydirectory) ) != NULL)
		{
			//hard link pro soucasnou i parent slozku, nachazi se v kazde slozce jako skryty objekt
			if (entry->d_name[0] != '.')
			{
				number_messages++;

				if (deleted_messages_vec.at(number_messages) == true)
				{
					if (list_uidl_message == number_messages)
					{
						response_buffer = "-ERR Message with number " + to_string(list_uidl_message) + " is marked as deleted. You can use RSET command to unmark all messages.\r\n";
						return EXIT_FAILURE;
					}
					else
					{
						deleted_messages++;
						continue;
					}
				}

				//funkce stat ze stejnojmenne knihovny vrati informace o souboru
				//scitame delky souboru, bude se hodit klientovi

				//vyuzijeme pomocneho stringu k nazvu souboru pridame i cestu k nemu
				temp.assign(entry->d_name);
				temp = path_to_files + temp;

				//jedna se o prepinac list, musime ukladat info o konkretnim souboru
				if (list_stat_uidl == LIST_CHOSEN)
				{
					if ((unsigned int) number_messages < message_sizes.size())
					{
						if (!list_uidl_message)
							response_buffer.append(to_string(number_messages) + " " + to_string(message_sizes.at(number_messages)) + "\r\n");

						else if (list_uidl_message == number_messages)
						{
							response_buffer = "+OK " + to_string(number_messages) + " " + to_string(message_sizes.at(number_messages)) + "\r\n";
							break;
						}
					}


				}

				else if (list_stat_uidl == UIDL_CHOSEN)
				{
					if (!list_uidl_message)
						response_buffer.append(to_string(number_messages) + " " + temp.assign(entry->d_name) + "\r\n");

					else if (list_uidl_message == number_messages)
					{
						response_buffer = "+OK " + to_string(number_messages) + " " + temp.assign(entry->d_name) + "\r\n";
						break;
					}	
				}	
			}	
		}

		// cyklus skoncil, mame celkove statistiky, je potreba je v nekterych situacich vyuzit
		//pokud se jedna o stat
		if (list_stat_uidl == STAT_CHOSEN)
		{
			//pocitali jsme si pocet smazanych zprav pomoci pomocne promenne, abychom nenarusili predchozi cyklus, ted je odecteme
			number_messages -= deleted_messages;

			//celkovy soucet octetu ve vectoru
			int number_octets = 0;
			for (unsigned i = 0; i < message_sizes.size(); ++i)
				number_octets += message_sizes.at(i);


			response_buffer = "+OK " + to_string(number_messages) + " " + to_string(number_octets) + "\r\n";
			return EXIT_SUCCESS;
		}

		//pokud byl zadan LIST nebo UIDL bez volitelneho [msg] je potreba take pridat nejaky udaj o celkove statistice
		else if (!list_uidl_message)
		{
			number_messages -= deleted_messages;

			//celkovy soucet octetu ve vectoru
			int number_octets = 0;
			for (unsigned i = 0; i < message_sizes.size(); ++i)
				number_octets += message_sizes.at(i);


			response_buffer = "+OK " + to_string(number_messages) + " " + to_string(number_octets) + "\r\n" + response_buffer;
			response_buffer.append(".\r\n");
			return EXIT_SUCCESS;
		}
		
		//avsak jeste je treti scenar, byl zadany LIST s [msg], ale ta nebyla nalezena, zadano prilis vysoke cislo
		else if ((list_uidl_message > number_messages) || (list_uidl_message < 1))
		{
			response_buffer = "-ERR There is no such message with number " + to_string(list_uidl_message) + " , only " + to_string(number_messages) + " messages in Maildir.\r\n";
			return EXIT_FAILURE;
		}


		//zavreme slozku
		closedir (mydirectory);
		return EXIT_SUCCESS;

	}

	//nepodarilo se slozku otevrit, bohuzel neda se pokracovat
	else
	{
		cerr << "## ERROR ## Could not open Maildir on set path " + directory_path + ".\r\n";
		exit (EXIT_FAILURE);
	}
	
	//******* warningy
	return EXIT_SUCCESS;
}

//funkce oznaci zpravu jako smazanou, skutecne smazani se vsak zde nedeje
int pop3_server::deleteMssg(int delete_mssg_number, string &response_buffer)
{
	//spocitame si pocet zprav a celkovou velikost
	int number_messages= 0, number_octets = 0;
	number_messages = message_sizes.size()-1;

	for (unsigned i = 0; i < message_sizes.size(); ++i)
		number_octets += message_sizes.at(i);
	
	//do funkce se mohlo dostat pouze int cislo, to vime, zde zkontrolujeme zda je pouzitelne
	if (delete_mssg_number < 1 || delete_mssg_number > number_messages)
	{
		response_buffer = "-ERR There is no such message with number " + to_string(delete_mssg_number) + ", so It cannot be deleted.\r\n";
		return EXIT_FAILURE;
	}

	//pokud se z nejakeho duvodu zmenil pocet zprav, neocekavanym zpusobem, presto se s tim vyporadame
	//a velikost vectoru zmenime
	if (deleted_messages_vec.size() != (unsigned) number_messages)
		//+1 protoze nechceme cislovat od 0, ta bude mrtva bunka
		deleted_messages_vec.resize(number_messages+1, false);

	//tento if kontroluje zda uz nebyla zprava marknuta jako smazana v minulosti, pouze kvuli vystupni zprave
	if (deleted_messages_vec.at(delete_mssg_number) == false)
	{
		deleted_messages_vec.at(delete_mssg_number) = true;
		response_buffer = "+OK Message number " + to_string(delete_mssg_number) + " was marked as deleted. All good sir.\r\n";
		return EXIT_SUCCESS;
	}

	else
	{
		response_buffer = "-ERR Message number " + to_string(delete_mssg_number) + " was already marked as deleted. Time is treasure.\r\n";
		return EXIT_FAILURE;
	}	

	//warning
	return EXIT_SUCCESS;
}

//funkce vsechny oznacene zpravy jako smazane odoznaci
int pop3_server::unmarkDeletedMssgs(string &response_buffer)
{
	//projdeme cely vector a vsechny hodnoty vyresetujeme na zakladni false, tedy ze zprava nebyla smazana
	for (unsigned i = 0; i < deleted_messages_vec.size(); ++i)
		deleted_messages_vec.at(i) = false;

	response_buffer = "+OK All messages marked as deleted were unmarked. \r\n";
	return EXIT_SUCCESS;
}	

int pop3_server::retrieveOrTopMssg(string &response_buffer, int retr_top, int top_retr_mssg_number, int number_of_lines)
{

	DIR *mydirectory;
	struct dirent *entry; 

	// + "Mailbox/cur"
	string path_to_files = directory_path + "cur/";
	if ( (mydirectory = opendir(path_to_files.c_str()) ) != NULL)
	{

        string choosen_filename, line;
		char read_char;
        int number_messages = 0, number_octets = 0, line_counter = -1;
        struct stat file_stats;
        FILE * retrieve_file;

        //prochazime soubory v otevrene slozce
		while ( (entry = readdir (mydirectory) ) != NULL)
		{
			//hard link pro soucasnou i parent slozku, nachazi se v kazde slozce jako skryty objekt
			if (entry->d_name[0] != '.')
			{
				
				number_messages++;	

				if (deleted_messages_vec.at(number_messages) == true)
				{
					if (number_messages == top_retr_mssg_number)
					{
						response_buffer = "-ERR Message with number " + to_string(top_retr_mssg_number) + " is marked as deleted. You can use RSET command to unmark all messages.\r\n";
						return EXIT_FAILURE;			
					}	
					else
						continue;		
				}
					

				//pokud se zrovna cte soubor s cislem, ktere ocekavame
				if (number_messages == top_retr_mssg_number)
				{
					//vyuzijeme pomocneho stringu k nazvu souboru pridame i cestu k nemu
					choosen_filename.assign(entry->d_name);
					choosen_filename = path_to_files + choosen_filename;

					if (stat(choosen_filename.c_str(), &file_stats) == 0)
						number_octets = file_stats.st_size;

					else
					{
						cerr << "## ERROR ## File " + choosen_filename + " is broken, information cannot be obtained.\r\n";
						continue;
					}

					response_buffer = "+OK " + to_string(number_octets) + " octets\r\n";  

					retrieve_file = fopen (choosen_filename.c_str(), "r");
					if (retrieve_file == NULL)
					{
						response_buffer = "-ERR Choosen file cannot be sent, file is probably broken, we are really sorry for that.\r\n";
						//return nebo EXIT????
						return EXIT_FAILURE;
					}

						
					while ((read_char = fgetc(retrieve_file)) != EOF)
					{ 
						//ulozime si char do stringu, budeme ho dale zkoumat, popripade kopirovat do response_bufferu
						line += read_char;

						if (retr_top == TOP_CHOSEN)
						{
							//konec hlavicky, prislo body
							if ((line.rfind("\r\n\r\n") != std::string::npos) || (line.rfind("\n\n") != std::string::npos) || (line.rfind("\n\r\n") != std::string::npos) || (line.rfind("\r\n\n") != std::string::npos))
							{
								if (number_of_lines == 0)				
									break;

								else if ((line.find("\r\n", line.length()-2, 2) != std::string::npos) || (line.find("\n", line.length()-1, 1) != std::string::npos))
								{
									line_counter++;
									if (number_of_lines == line_counter)
										break;
								}

							}
						}

					}

					if (number_of_lines < 0)
					{
						response_buffer = "-ERR There is no line with number " + to_string(number_of_lines) + " , only " + to_string(line_counter) + " lines in file.\r\n";
						return EXIT_FAILURE;
					}

					//pridat \n -> \r\n
					unsigned int len_of_line = line.length();
 					for (unsigned int i = 0; i < len_of_line; ++i)
 					{
 						//kdyby tam nahodou byl prvni znak \n
 						if (line.length() > 1)
 						{
 							if ((line[i] == '\n') && (line[i-1] != '\r'))
 							{
 								line.insert(i, 1, '\r');
 								i++;
 								len_of_line++;
 							}

 						}

 						else if ((line.length() == 1) && (line.at(0) == '\n'))
 							line = '\r' + line;

 					}

					response_buffer.append(line);
					//+CRLF?
					response_buffer.append(".\r\n");
					
					//zase zavreme soubor
					fclose(retrieve_file);
					//a vyskocime z while cyklu, prace je hotova
					break;
			
				}

			}	
		}
			
		//zavreme slozku
		closedir (mydirectory);

		if (number_messages < top_retr_mssg_number)
		{
			response_buffer = "-ERR There is no such message with number " + to_string(top_retr_mssg_number) + ", so It cannot be retrieved.\r\n";
			return EXIT_FAILURE;
		}

		return EXIT_SUCCESS;
	}

	//nepodarilo se slozku otevrit, bohuzel neda se pokracovat
	else
	{
		cerr << "## ERROR ## Could not open Maildir on set path " + directory_path + ".\r\n";
		exit (EXIT_FAILURE);
	}
	
}


bool pop3_server::newToCur(char **argv)
{
	//mrtva bunka, zmena indexace, zaciname od 1
	message_sizes.push_back(0);

	DIR *mydirectory;
	struct dirent *entry; 


	string path_to_new = directory_path + "new/";
	string path_to_cur = directory_path + "cur/";

	if ( (mydirectory = opendir(path_to_new.c_str()) ) != NULL)
	{

        string path_file_in_new, path_file_in_cur, line, choosen_filename;
		char read_char, last_char;
        FILE *file_in_new, *file_in_cur, *changes_in_Maildir;
     	int size_of_message;


        string filename = argv[0];
        
        //zjistime si cestu k popser. Kdyby se nahodou program nespoustel z adresare, kde je umisten
        size_t pos = filename.rfind("popser");
        //neni potreba, nikdy nenastane, ale clovek nikdy nevi
        if (pos != std::string::npos)
        	filename = filename.substr(0, pos);

        filename = filename + "changes_in_Maildir";

        //vytvorime soubor v slozce s pop3 serverem a budeme si poznamenavat zmeny v slozce Maildir, budou potreba pri resetu
		changes_in_Maildir = fopen (filename.c_str(), "w");
		if (changes_in_Maildir == NULL)
			cerr <<  "## ERROR ## File for changes in Maldir cannot be created.\r\n";

        //prochazime soubory v otevrene slozce
		while ( (entry = readdir (mydirectory) ) != NULL)
		{
			//hard link pro soucasnou i parent slozku, nachazi se v kazde slozce jako skryty objekt
			if (entry->d_name[0] != '.')
			{
					size_of_message = 0;
					//vyuzijeme pomocneho stringu k nazvu souboru pridame i cestu k nemu
					choosen_filename.assign(entry->d_name);
					path_file_in_new = path_to_new + choosen_filename;
					path_file_in_cur = path_to_cur + choosen_filename;

					file_in_new = fopen (path_file_in_new.c_str(), "r");
					if (file_in_new == NULL)
					{
						cerr <<  "## ERROR ## File " + choosen_filename + " cannot be sent from new to cur, file is probably broken.\r\n";
						continue;
					}

					//vytvorime soubor v slozce cur a budeme tam chrlit data
					file_in_cur = fopen (path_file_in_cur.c_str(), "w");
					if (file_in_cur == NULL)
					{
						cerr <<  "## ERROR ## File " +  choosen_filename + " cannot be transfered to cur, file is probably broken.\r\n";
						fclose(file_in_new);
						continue;
					}

					line = "";
					last_char = ' ';

					//cteme soubor znak po znaku
					while ((read_char = fgetc(file_in_new)) != EOF)
					{
						//ulozime si char do stringu
						line += read_char;
						size_of_message++;

						//chybejici CR, pricteme ho i tak yay? 
						if ((last_char != '\r') && (read_char == '\n'))	
							size_of_message++;	

						last_char = read_char;
					}	

					//pokud nebyl soubor ukoncen patricne, ten nas soucet to napravi
					if ((read_char == EOF) && (last_char != '\n'))
						size_of_message = size_of_message + 2;


					message_sizes.push_back(size_of_message);


					fprintf(file_in_cur,  "%s", line.c_str());

					string temp = path_file_in_cur + " -> " + path_file_in_new;
					fprintf(changes_in_Maildir, "%s\r\n", temp.c_str());
					//zase zavreme soubor
					fclose(file_in_new);	
					if (remove(path_file_in_new.c_str()) != 0)
						cerr <<  "## ERROR ## File " + choosen_filename +  " in /new/ cannot be deleted.\r\n";
			
					fclose(file_in_cur);

			}	
		}
		
		//zavreme soubor o zmenach
		fclose(changes_in_Maildir);					
		//zavreme slozku
		closedir (mydirectory);

		int number_messages = message_sizes.size()-1;
		//rozsirime si vector pro zaznamenavani zprav, zda jsou smazany nebo ne, protoze jsme zjistili pocatecni pocet zprav
		if (deleted_messages_vec.size() != (unsigned) (number_messages))
			//+1 protoze nechceme cislovat od 0, to bude mrtva bunka
			deleted_messages_vec.resize(number_messages + 1, false);

		return EXIT_SUCCESS;
	}

	//nepodarilo se slozku otevrit, bohuzel neda se pokracovat
	else
	{
		cerr << "## ERROR ## Could not open Maildir on set path " + directory_path + ".\r\n";
		exit (EXIT_FAILURE);
	}
	
}


//resetuje stav serveru do puvodniho. Smaze pomocne soubory presune zpet co byvalo v Maildir/new
bool pop3_server::resetParameter(char **argv)
{
	string newToCurTransfer, line;
	char read_char;

	FILE *file_in_new, *file_in_cur, *changes_in_Maildir;

	string filename = argv[0];

    //zjistime si cestu k popser. Kdyby se nahodou program nespoustel z adresare, kde je umisten
    size_t pos = filename.rfind("popser");
    //neni potreba, nikdy nenastane, ale clovek nikdy nevi
    if (pos != std::string::npos)
    	filename = filename.substr(0, pos);

    filename = filename + "changes_in_Maildir";

	//vytvorime soubor v slozce s pop3 serverem a budeme si poznamenavat zmeny v slozce Maildir, budou potreba pri resetu
	changes_in_Maildir = fopen (filename.c_str(), "r");
	if (changes_in_Maildir == NULL)
	{
		cerr <<  "## ERROR ## File for changes in Maldir cannot be opened.\r\n";
		return EXIT_FAILURE;
	}	

	while ((read_char = fgetc(changes_in_Maildir)) != EOF)
	{
		//ulozime si char do stringu, budeme ho dale zkoumat, popripade kopirovat do response_bufferu
		newToCurTransfer += read_char;
		

		//zjistime zda jiz nastal konec radku
		if (newToCurTransfer.rfind("\r\n") != std::string::npos)
		{
			//smazeme crlf
			newToCurTransfer.erase(newToCurTransfer.length()-2, 2);	
			string path_file_in_cur = newToCurTransfer.substr(0, newToCurTransfer.find(" -> "));

			//4 = delka " -> "
			string path_file_in_new = newToCurTransfer.substr(newToCurTransfer.find(" -> ") + 4, newToCurTransfer.length() - newToCurTransfer.find(" -> ") - 4);


			//precetli jsme prvni nazev souboru
			file_in_cur = fopen (path_file_in_cur.c_str(), "r");
			if (file_in_cur == NULL)
			{
				//cerr <<  "## ERROR ## File " + choosen_filename + " cannot be sent from cur to new, file is probably broken.\r\n";
				newToCurTransfer = "";	
				continue;
			}

			line = "";

			while ((read_char = fgetc(file_in_cur)) != EOF)
				//ulozime si char do stringu
				line += read_char;
	

			//vytvorime soubor v new a vratime do nej informace
			file_in_new = fopen (path_file_in_new.c_str(), "w");
			if (file_in_new == NULL)
			{
				cerr <<  "## ERROR ## File " + newToCurTransfer + " cannot be transfered from cur to new, file is probably broken.\r\n";
				fclose(file_in_cur);
				newToCurTransfer = "";	
				continue;
			}

			//zapiseme obash do noveho souboru
			fprintf(file_in_new,  "%s", line.c_str());
			
			//soubory zavreme
			fclose(file_in_new);	
			fclose(file_in_cur);

			if (remove(path_file_in_cur.c_str()) != 0)
				cerr <<  "## ERROR ## File " + newToCurTransfer +  " in /cur/ cannot be deleted.\r\n";
			

			newToCurTransfer = "";	
		}

	}	

	if (remove(filename.c_str()) != 0)
		cerr <<  "## ERROR ## File changes_in_Maildir in popser directory cannot be deleted.\r\n";

	return EXIT_SUCCESS;

}

//smazeme zpravy oznacene jako deleted
void pop3_server::realMessageDelete(string &response_buffer)
{
	DIR *mydirectory;
	struct dirent *entry; 

	int number_messages = 0, messages_deleted = 0;
	string filename, path_file_in_cur;
	bool unable_to_remove = false;

	string path_to_files = directory_path + "cur/";
	if ( (mydirectory = opendir(path_to_files.c_str()) ) != NULL)
	{

		while ( (entry = readdir (mydirectory) ) != NULL)
		{
			//hard link pro soucasnou i parent slozku, nachazi se v kazde slozce jako skryty objekt
			if (entry->d_name[0] != '.')
			{
				number_messages++;
				if (deleted_messages_vec.at(number_messages) == true)
				{

					//smazeme zpravu i z vectoru o velikostech
					message_sizes.erase(message_sizes.begin() + number_messages);

					filename.assign(entry->d_name);
					path_file_in_cur = path_to_files + filename;
					if (remove(path_file_in_cur.c_str()) != 0)
					{
						cerr <<  "## ERROR ## File " + filename +  " cannot be deleted in UPDATE state.\r\n";
						response_buffer = "-ERR some deleted messages not removed.\r\n";
						unable_to_remove = true;
					}

					else
						messages_deleted++;

				}

			}
		}
	}


	//projdeme cely vector a vsechny hodnoty vyresetujeme na zakladni false, tedy ze zprava nebyla smazana
	for (unsigned i = 0; i < deleted_messages_vec.size(); ++i)
			deleted_messages_vec.at(i) = false;
	
	//pokud nesel soubor smazat
	if (!(unable_to_remove))
		response_buffer = "+OK POP3 server signing you off. " + to_string(number_messages - messages_deleted) + " messages left in Maildir.\r\n";

	closedir(mydirectory);
	return;
}

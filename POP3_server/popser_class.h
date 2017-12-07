//#include "libraries.h"
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <mutex>
#include <vector>

class pop3_server
{
public:
	std::string	user, pass, directory_path, file_path, time_stamp;
	bool c_set = false, user_found = false;
	std::vector<bool> deleted_messages_vec {false};
	std::mutex access_locker;
public:
	int authorization (std::string &entry_buffer, std::string &response_buffer);
	int getPassword (std::string &entry_buffer, std::string &response_buffer);
	int checkDirectory (int *number_messages, int *number_octets);
	int checkLoginFile (std::string &response_buffer);
	int transaction (std::string &entry_buffer, std::string &response_buffer);
	int listOrStatOrUidl (std::string &response_buffer, int list_stat_uidl, int list_uidl_message = 0);
	int deleteMssg (int delete_mssg_number, std::string &response_buffer);
	int unmarkDeletedMssgs(std::string &response_buffer);
	int retrieveOrTopMssg(std::string &response_buffer, int retr_top, int top_retr_mssg_number, int number_of_lines = 0);
	bool newToCur(char **argv);
	bool resetParameter(char **argv);
	void realMessageDelete(std::string &response_buffer);
};

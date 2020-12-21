# discordGrabber
Grabs user information like username userid token email etc. 

<img src="https://jelbrek.icu/kb3x691m.png">

#### This is for applications who want to identify the person via discord, without asking them ;)

Grabs user information via reading memory:
```
environment - string
release - string
email - string
id - string
username - string
token - string
2fa - bool
```
### Requirements:
- [nlohmann/json](https://github.com/nlohmann/json)

### Tested on:
- Release - Everything works fine.
- PTB - Everything works fine.
- Canary - Buggy (cant find JSON).
### Update:
- 8 Hours after release discord is already trying to fight it by.. not having the explorer parent anymore?
  Fixed it by just checking if the wstring of the parent is empty.
- A bug occured where the parents of all processes were discord(...).exe 
  which wasnt true when looked at in process hacker 2.
- Death of the project: discord deleted the json and i cant find any email/userid or anything that is static in memory.

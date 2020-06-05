# discordGrabber
grabs userid username and build info off discord.

example: 
`{"environment":"ptb","release":"0.0.52","user":{"email":"censored@gmail.com","id":"55278871908739249","username":"censored"}}`

### This is for learning purposes.

#### This is for applications who want to identify the person via discord, without asking them ;)


### Requirements:
- [lohmann/json](https://github.com/nlohmann/json)

### Tested on:
- PTB 

### Update:
- 8 Hours after release discord is already trying to fight it by.. not having the explorer parent anymore?
  Fixed it by just checking if the wstring of the parent is empty.
